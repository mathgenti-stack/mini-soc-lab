"""A small jq for the simulated bash: the filters used to read sign-in logs and other JSON.

Supported: . .a .a.b ."a" .[n] .[] .[a:b] ? | , // and or not, comparisons, + - * / %, array and
object construction, string interpolation "\\(.x)", if/then/elif/else/end, `as $x`, and the
functions length, keys, values, select, map, map_values, sort, sort_by, group_by, unique, unique_by,
min, max, min_by, max_by, add, first, last, reverse, has, contains, test, startswith, endswith,
ascii_downcase, ascii_upcase, tostring, tonumber, type, empty, to_entries, from_entries,
with_entries, join, split, ltrimstr, rtrimstr, any, all, range, limit, flatten, tojson, fromjson,
@csv, @tsv and @text. Not supported: paths, reduce, foreach, def and modules.
"""

from __future__ import annotations

import json
import re

from .core import ShellError, Unsupported


class JqError(ShellError):
    pass


# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------
TOKEN = re.compile(r"""
    (?P<space>\s+)
  | (?P<number>\d+\.?\d*(?:[eE][-+]?\d+)?)
  | (?P<string>")
  | (?P<format>@[a-z0-9]+)
  | (?P<var>\$[A-Za-z_]\w*)
  | (?P<field>\.[A-Za-z_]\w*)
  | (?P<ident>[A-Za-z_]\w*(?:::\w+)?)
  | (?P<op>\?//|//=|\|=|\+=|-=|==|!=|<=|>=|//|\.\.|[.\[\]{}()|,:;<>+\-*/%?])
""", re.VERBOSE)


def tokenize(source: str) -> list[tuple[str, object]]:
    tokens = []
    i = 0
    while i < len(source):
        match = TOKEN.match(source, i)
        if not match:
            raise JqError(f"jq: error: syntax error, unexpected '{source[i]}' (Unix shell quoting issues?)")
        kind = match.lastgroup
        if kind == "space":
            i = match.end()
            continue
        if kind == "string":
            parts, i = _string(source, match.end())
            tokens.append(("string", parts))
            continue
        value = match.group(0)
        if kind == "number":
            value = float(value) if any(c in value for c in ".eE") else int(value)
        tokens.append((kind, value))
        i = match.end()
    tokens.append(("eof", None))
    return tokens


def _string(source: str, i: int) -> tuple[list, int]:
    """A string literal; returns [text or ('interp', source)] parts and the index after the quote."""
    parts: list = []
    buf = []
    while i < len(source):
        ch = source[i]
        if ch == '"':
            if buf:
                parts.append("".join(buf))
            return parts, i + 1
        if ch == "\\" and i + 1 < len(source):
            nxt = source[i + 1]
            if nxt == "(":
                depth = 1
                j = i + 2
                while j < len(source) and depth:
                    depth += {"(": 1, ")": -1}.get(source[j], 0)
                    j += 1
                if buf:
                    parts.append("".join(buf))
                    buf = []
                parts.append(("interp", source[i + 2:j - 1]))
                i = j
                continue
            buf.append({"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\", "/": "/"}.get(nxt, nxt))
            i += 2
            continue
        buf.append(ch)
        i += 1
    raise JqError("jq: error: unterminated string")


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------
class Parser:
    def __init__(self, source: str):
        self.tokens = tokenize(source)
        self.pos = 0

    def peek(self, offset=0):
        return self.tokens[min(self.pos + offset, len(self.tokens) - 1)]

    def take(self):
        token = self.tokens[self.pos]
        self.pos += 1
        return token

    def at(self, kind, value=None):
        k, v = self.peek()
        return k == kind and (value is None or v == value)

    def at_op(self, *values):
        k, v = self.peek()
        return k == "op" and v in values

    def expect(self, value):
        k, v = self.peek()
        if not ((k == "op" or k == "ident") and v == value):
            raise JqError(f"jq: error: syntax error, expected '{value}' but got {v!r}")
        return self.take()

    def parse(self):
        node = self.pipe()
        if not self.at("eof"):
            raise JqError(f"jq: error: syntax error, unexpected {self.peek()[1]!r}")
        return node

    def pipe(self):
        left = self.comma()
        if self.at("ident", "as"):
            self.take()
            name = self.take()
            if name[0] != "var":
                raise JqError("jq: error: syntax error after 'as'")
            self.expect("|")
            return ("as", left, name[1], self.pipe())
        if self.at_op("|"):
            self.take()
            return ("pipe", left, self.pipe())
        return left

    def comma(self):
        left = self.alternative()
        while self.at_op(","):
            self.take()
            left = ("comma", left, self.alternative())
        return left

    def alternative(self):
        left = self.or_expr()
        if self.at_op("//"):
            self.take()
            return ("alt", left, self.alternative())
        if self.at_op("|=", "+=", "-=", "//="):
            raise Unsupported("jq: update assignments are not supported in the simulated terminal")
        return left

    def or_expr(self):
        left = self.and_expr()
        while self.at("ident", "or"):
            self.take()
            left = ("or", left, self.and_expr())
        return left

    def and_expr(self):
        left = self.compare()
        while self.at("ident", "and"):
            self.take()
            left = ("and", left, self.compare())
        return left

    def compare(self):
        left = self.additive()
        if self.at_op("==", "!=", "<", "<=", ">", ">="):
            op = self.take()[1]
            return ("cmp", op, left, self.additive())
        return left

    def additive(self):
        left = self.multiplicative()
        while self.at_op("+", "-"):
            op = self.take()[1]
            left = ("arith", op, left, self.multiplicative())
        return left

    def multiplicative(self):
        left = self.unary()
        while self.at_op("*", "/", "%"):
            op = self.take()[1]
            left = ("arith", op, left, self.unary())
        return left

    def unary(self):
        if self.at_op("-"):
            self.take()
            return ("arith", "-", ("literal", 0), self.postfix())
        return self.postfix()

    def postfix(self):
        node = self.term()
        while True:
            if self.at("field"):
                node = ("pipe", node, ("field", self.take()[1][1:]))
            elif self.at_op(".") and self.peek(1)[0] == "string":
                self.take()
                node = ("pipe", node, ("field", self._plain(self.take()[1])))
            elif self.at_op(".") and self.peek(1) == ("op", "["):
                self.take()
            elif self.at_op("["):
                node = ("pipe", node, self.bracket())
            elif self.at_op("?"):
                self.take()
                node = ("try", node)
            else:
                return node

    def _plain(self, parts) -> str:
        if any(isinstance(p, tuple) for p in parts):
            raise JqError("jq: error: interpolation is not allowed in a field name")
        return "".join(parts)

    def bracket(self):
        self.take()  # [
        if self.at_op("]"):
            self.take()
            return ("iterate",)
        if self.at_op(":"):
            self.take()
            end = self.pipe()
            self.expect("]")
            return ("slice", None, end)
        index = self.pipe()
        if self.at_op(":"):
            self.take()
            end = None if self.at_op("]") else self.pipe()
            self.expect("]")
            return ("slice", index, end)
        self.expect("]")
        return ("index", index)

    def term(self):
        kind, value = self.peek()
        if kind == "op" and value == ".":
            self.take()
            if self.at("string"):
                return ("field", self._plain(self.take()[1]))
            if self.at_op("["):
                return self.bracket()
            return ("identity",)
        if kind == "op" and value == "..":
            self.take()
            return ("recurse",)
        if kind == "field":
            self.take()
            return ("field", value[1:])
        if kind == "number":
            self.take()
            return ("literal", value)
        if kind == "string":
            self.take()
            return self.string_node(value)
        if kind == "format":
            self.take()
            if self.at("string"):
                return ("format_string", value, self.string_node(self.take()[1]))
            return ("format", value)
        if kind == "var":
            self.take()
            return ("var", value)
        if kind == "op" and value == "(":
            self.take()
            node = self.pipe()
            self.expect(")")
            return node
        if kind == "op" and value == "[":
            self.take()
            if self.at_op("]"):
                self.take()
                return ("array", None)
            node = self.pipe()
            self.expect("]")
            return ("array", node)
        if kind == "op" and value == "{":
            return self.object()
        if kind == "ident":
            self.take()
            if value in ("true", "false", "null"):
                return ("literal", {"true": True, "false": False, "null": None}[value])
            if value == "if":
                return self.if_node()
            if value in ("reduce", "foreach", "def", "import", "include", "label", "try"):
                raise Unsupported(f"jq: '{value}' is not supported in the simulated terminal")
            args = []
            if self.at_op("("):
                self.take()
                args.append(self.pipe())
                while self.at_op(";"):
                    self.take()
                    args.append(self.pipe())
                self.expect(")")
            return ("call", value, args)
        raise JqError(f"jq: error: syntax error, unexpected {value!r}" if kind != "eof"
                      else "jq: error: syntax error, unexpected end of file")

    def string_node(self, parts):
        nodes = [p if isinstance(p, str) else Parser(p[1]).parse() for p in parts]
        if all(isinstance(n, str) for n in nodes):
            return ("literal", "".join(nodes))
        return ("interp", nodes)

    def if_node(self):
        cond = self.pipe()
        self.expect("then")
        then = self.pipe()
        if self.at("ident", "elif"):
            self.take()
            return ("if", cond, then, self.if_node())
        other = None
        if self.at("ident", "else"):
            self.take()
            other = self.pipe()
        self.expect("end")
        return ("if", cond, then, other)

    def object(self):
        self.take()  # {
        entries = []
        while not self.at_op("}"):
            kind, value = self.take()
            if kind in ("ident", "field"):
                key = ("literal", value.lstrip("."))
            elif kind == "string":
                key = self.string_node(value)
            elif kind == "var":
                entries.append((("literal", value[1:]), ("var", value)))
                if self.at_op(","):
                    self.take()
                continue
            elif kind == "op" and value == "(":
                key = self.pipe()
                self.expect(")")
            else:
                raise JqError("jq: error: syntax error in object construction")
            if self.at_op(":"):
                self.take()
                val = self.alternative_no_comma()
            else:
                val = ("field", key[1])
            entries.append((key, val))
            if self.at_op(","):
                self.take()
        self.take()
        return ("object", entries)

    def alternative_no_comma(self):
        left = self.alternative()
        while self.at_op("|"):
            self.take()
            left = ("pipe", left, self.alternative())
        return left


# ---------------------------------------------------------------------------
# Evaluation (each filter returns a list of outputs)
# ---------------------------------------------------------------------------
TYPE_ORDER = {type(None): 0, bool: 1, int: 2, float: 2, str: 3, list: 4, dict: 5}


def type_name(value) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    return "object"


def sort_key(value):
    rank = TYPE_ORDER[type(value)] if type(value) in TYPE_ORDER else 9
    if isinstance(value, list):
        return (rank, [sort_key(v) for v in value])
    if isinstance(value, dict):
        return (rank, sorted(value), [sort_key(value[k]) for k in sorted(value)])
    if value is None:
        return (rank, 0)
    return (rank, value)


def normalise_number(value):
    if isinstance(value, float) and value.is_integer() and abs(value) < 1e17:
        return int(value)
    return value


def describe(value) -> str:
    text = json.dumps(value, ensure_ascii=False)
    return f"{type_name(value)} ({text[:11]}{'...' if len(text) > 11 else ''})"


class Jq:
    def __init__(self, program: str, variables: dict | None = None):
        self.tree = Parser(program).parse()
        self.variables = {f"${k}": v for k, v in (variables or {}).items()}
        self.variables.setdefault("$ENV", {})

    def run(self, value) -> list:
        return self.eval(self.tree, value, self.variables)

    def eval(self, node, value, env) -> list:
        kind = node[0]
        if kind == "identity":
            return [value]
        if kind == "recurse":
            out = []

            def walk(v):
                out.append(v)
                if isinstance(v, list):
                    for item in v:
                        walk(item)
                elif isinstance(v, dict):
                    for item in v.values():
                        walk(item)
            walk(value)
            return out
        if kind == "literal":
            return [node[1]]
        if kind == "var":
            if node[1] not in env:
                raise JqError(f"jq: error: {node[1]} is not defined")
            return [env[node[1]]]
        if kind == "field":
            return [self.index(value, node[1])]
        if kind == "index":
            return [self.index(value, key) for key in self.eval(node[1], value, env)]
        if kind == "slice":
            starts = self.eval(node[1], value, env) if node[1] else [None]
            ends = self.eval(node[2], value, env) if node[2] else [None]
            if value is None:
                return [None]
            if not isinstance(value, (list, str)):
                raise JqError(f"jq: error: Cannot index {type_name(value)} with object")
            return [value[s:e] for s in starts for e in ends]
        if kind == "iterate":
            if isinstance(value, list):
                return list(value)
            if isinstance(value, dict):
                return list(value.values())
            raise JqError(f"jq: error: Cannot iterate over {describe(value)}")
        if kind == "pipe":
            return [out for left in self.eval(node[1], value, env) for out in self.eval(node[2], left, env)]
        if kind == "comma":
            return self.eval(node[1], value, env) + self.eval(node[2], value, env)
        if kind == "as":
            out = []
            for bound in self.eval(node[1], value, env):
                out += self.eval(node[3], value, {**env, node[2]: bound})
            return out
        if kind == "try":
            try:
                return self.eval(node[1], value, env)
            except JqError:
                return []
        if kind == "alt":
            try:
                left = [v for v in self.eval(node[1], value, env) if v not in (None, False)]
            except JqError:
                left = []
            return left or self.eval(node[2], value, env)
        if kind in ("and", "or"):
            out = []
            for a in self.eval(node[1], value, env):
                if kind == "and" and not truthy(a):
                    out.append(False)
                elif kind == "or" and truthy(a):
                    out.append(True)
                else:
                    out += [truthy(b) for b in self.eval(node[2], value, env)]
            return out
        if kind == "cmp":
            op = node[1]
            out = []
            for b in self.eval(node[3], value, env):
                for a in self.eval(node[2], value, env):
                    ka, kb = sort_key(a), sort_key(b)
                    out.append({"==": a == b and type_name(a) == type_name(b), "!=": not (a == b and type_name(a) == type_name(b)),
                                "<": ka < kb, "<=": ka <= kb, ">": ka > kb, ">=": ka >= kb}[op])
            return out
        if kind == "arith":
            return [self.arith(node[1], a, b) for b in self.eval(node[3], value, env)
                    for a in self.eval(node[2], value, env)]
        if kind == "array":
            return [[] if node[1] is None else self.eval(node[1], value, env)]
        if kind == "object":
            results = [{}]
            for key_node, val_node in node[1]:
                new = []
                for partial in results:
                    for key in self.eval(key_node, value, env):
                        if not isinstance(key, str):
                            raise JqError(f"jq: error: Object keys must be strings")
                        for val in self.eval(val_node, value, env):
                            new.append({**partial, key: val})
                results = new
            return results
        if kind == "interp":
            outputs = [""]
            for part in node[1]:
                if isinstance(part, str):
                    outputs = [o + part for o in outputs]
                else:
                    outputs = [o + (v if isinstance(v, str) else dumps(v, compact=True))
                               for o in outputs for v in self.eval(part, value, env)]
            return outputs
        if kind == "if":
            out = []
            for cond in self.eval(node[1], value, env):
                if truthy(cond):
                    out += self.eval(node[2], value, env)
                elif node[3] is not None:
                    out += self.eval(node[3], value, env)
                else:
                    out.append(value)
            return out
        if kind == "format":
            return [self.format(node[1], value)]
        if kind == "format_string":
            parts = node[2][1] if node[2][0] == "interp" else [node[2][1]]
            outputs = [""]
            for part in parts:
                if isinstance(part, str):
                    outputs = [o + part for o in outputs]
                else:
                    outputs = [o + self.format(node[1], v) for o in outputs for v in self.eval(part, value, env)]
            return outputs
        if kind == "call":
            return self.call(node[1], node[2], value, env)
        raise JqError(f"jq: error: cannot evaluate {kind}")

    @staticmethod
    def index(value, key):
        if value is None:
            return None
        if isinstance(key, str):
            if not isinstance(value, dict):
                raise JqError(f'jq: error: Cannot index {type_name(value)} with "{key}"')
            return value.get(key)
        if isinstance(key, (int, float)) and not isinstance(key, bool):
            if not isinstance(value, list):
                raise JqError(f"jq: error: Cannot index {type_name(value)} with number")
            i = int(key)
            if -len(value) <= i < len(value):
                return value[i]
            return None
        raise JqError(f"jq: error: Cannot index {type_name(value)} with {type_name(key)}")

    @staticmethod
    def arith(op, a, b):
        if op == "+":
            if a is None:
                return b
            if b is None:
                return a
            if isinstance(a, (int, float)) and isinstance(b, (int, float)) and not isinstance(a, bool):
                return normalise_number(a + b)
            if isinstance(a, str) and isinstance(b, str):
                return a + b
            if isinstance(a, list) and isinstance(b, list):
                return a + b
            if isinstance(a, dict) and isinstance(b, dict):
                return {**a, **b}
        elif op == "-":
            if isinstance(a, (int, float)) and isinstance(b, (int, float)):
                return normalise_number(a - b)
            if isinstance(a, list) and isinstance(b, list):
                return [x for x in a if x not in b]
        elif op in "*/%" and isinstance(a, (int, float)) and isinstance(b, (int, float)):
            if op != "*" and b == 0:
                raise JqError(f"jq: error: {describe(a)} and {describe(b)} cannot be divided because the divisor is zero")
            if op == "*":
                return normalise_number(a * b)
            if op == "/":
                return normalise_number(a / b)
            return int(a) % int(b)
        elif op == "/" and isinstance(a, str) and isinstance(b, str):
            return a.split(b)
        verb = {"+": "added", "-": "subtracted", "*": "multiplied", "/": "divided", "%": "divided"}[op]
        raise JqError(f"jq: error: {describe(a)} and {describe(b)} cannot be {verb}")

    def format(self, name, value) -> str:
        if name == "@text":
            return value if isinstance(value, str) else dumps(value, compact=True)
        if name == "@json":
            return dumps(value, compact=True)
        if name in ("@csv", "@tsv"):
            if not isinstance(value, list):
                raise JqError(f"jq: error: {describe(value)} cannot be {name[1:]}-formatted, only an array can be")
            cells = []
            for item in value:
                if isinstance(item, str):
                    cells.append('"' + item.replace('"', '""') + '"' if name == "@csv"
                                 else item.replace("\\", "\\\\").replace("\t", "\\t"))
                elif item is None:
                    cells.append("")
                else:
                    cells.append(dumps(item, compact=True))
            return ("," if name == "@csv" else "\t").join(cells)
        raise Unsupported(f"jq: format {name} is not supported in the simulated terminal")

    def call(self, name, args, value, env) -> list:
        def one(i=0):
            return self.eval(args[i], value, env)

        def need(kinds, what):
            if not isinstance(value, kinds):
                raise JqError(f"jq: error: {describe(value)} {what}")

        if name == "empty":
            return []
        if name == "not":
            return [not truthy(value)]
        if name == "length":
            if value is None:
                return [0]
            if isinstance(value, bool):
                raise JqError(f"jq: error: boolean ({json.dumps(value)}) has no length")
            if isinstance(value, (int, float)):
                return [abs(value)]
            return [len(value)]
        if name in ("keys", "keys_unsorted"):
            if isinstance(value, dict):
                return [sorted(value) if name == "keys" else list(value)]
            if isinstance(value, list):
                return [list(range(len(value)))]
            raise JqError(f"jq: error: {describe(value)} has no keys")
        if name == "values":
            return [value] if value is not None else []
        if name == "select":
            return [value for cond in one() if truthy(cond)]
        if name == "map":
            need((list, dict), "cannot be iterated over")
            items = value if isinstance(value, list) else list(value.values())
            return [[out for item in items for out in self.eval(args[0], item, env)]]
        if name == "map_values":
            need((list, dict), "cannot be iterated over")
            if isinstance(value, list):
                return [[self.eval(args[0], item, env)[0] for item in value]]
            return [{k: self.eval(args[0], v, env)[0] for k, v in value.items()}]
        if name in ("sort", "unique", "reverse", "min", "max", "add", "first", "last", "flatten", "to_entries",
                    "from_entries", "any", "all", "transpose") and not args:
            if name == "reverse" and isinstance(value, str):
                return [value[::-1]]
            if name in ("first", "last") and value is None:
                return [None]
            if name == "to_entries":
                need(dict, "has no keys")
                return [[{"key": k, "value": v} for k, v in value.items()]]
            need(list, f"cannot be {'sorted' if name in ('sort', 'unique') else 'iterated over'}, as it is not an array"
                 if name in ("sort", "unique") else "cannot be iterated over")
            if name == "sort":
                return [sorted(value, key=sort_key)]
            if name == "unique":
                out = []
                for item in sorted(value, key=sort_key):
                    if not out or out[-1] != item:
                        out.append(item)
                return [out]
            if name == "reverse":
                return [value[::-1]]
            if name in ("min", "max"):
                return [(min if name == "min" else max)(value, key=sort_key) if value else None]
            if name == "add":
                total = None
                for item in value:
                    total = self.arith("+", total, item)
                return [total]
            if name == "first":
                return [value[0]] if value else []
            if name == "last":
                return [value[-1]] if value else []
            if name == "flatten":
                def flat(items):
                    for item in items:
                        if isinstance(item, list):
                            yield from flat(item)
                        else:
                            yield item
                return [list(flat(value))]
            if name == "from_entries":
                return [{str(e.get("key", e.get("name", e.get("k")))): e.get("value", e.get("v")) for e in value}]
            if name == "any":
                return [any(truthy(v) for v in value)]
            if name == "all":
                return [all(truthy(v) for v in value)]
        if name in ("first", "last") and args:
            outputs = one()
            return outputs[:1] if name == "first" else outputs[-1:]
        if name in ("any", "all") and args:
            need(list, "cannot be iterated over")
            results = [truthy(out) for item in value for out in self.eval(args[0], item, env)]
            return [any(results) if name == "any" else all(results)]
        if name in ("sort_by", "group_by", "unique_by", "min_by", "max_by"):
            need(list, "cannot be sorted, as it is not an array")
            keyed = [(sort_key(self.eval(args[0], item, env)), index, item) for index, item in enumerate(value)]
            keyed.sort(key=lambda entry: (entry[0], entry[1]))
            if name == "sort_by":
                return [[item for _, _, item in keyed]]
            if name in ("min_by", "max_by"):
                if not keyed:
                    return [None]
                return [keyed[0][2] if name == "min_by" else keyed[-1][2]]
            groups: list[list] = []
            last = object()
            for key, _, item in keyed:
                if key != last:
                    groups.append([])
                    last = key
                groups[-1].append(item)
            return [groups if name == "group_by" else [g[0] for g in groups]]
        if name == "with_entries":
            need(dict, "has no keys")
            entries = [{"key": k, "value": v} for k, v in value.items()]
            mapped = [out for e in entries for out in self.eval(args[0], e, env)]
            return [{str(e["key"]): e.get("value") for e in mapped}]
        if name == "has":
            return [(key in value) if isinstance(value, dict) else (0 <= key < len(value)) for key in one()]
        if name == "contains":
            return [contains(value, other) for other in one()]
        if name in ("test", "match", "capture"):
            need(str, "cannot be matched, as it is not a string")
            out = []
            for pattern in one():
                flags = self.eval(args[1], value, env)[0] if len(args) > 1 else ""
                regex = re.compile(pattern, re.IGNORECASE if "i" in (flags or "") else 0)
                found = regex.search(value)
                if name == "test":
                    out.append(bool(found))
                elif name == "capture":
                    if found:
                        out.append(found.groupdict())
                elif found:
                    out.append({"offset": found.start(), "length": found.end() - found.start(), "string": found.group(0),
                                "captures": []})
            return out
        if name in ("startswith", "endswith", "ltrimstr", "rtrimstr", "split", "join", "ascii_downcase",
                    "ascii_upcase", "ltrim", "rtrim", "trim"):
            if name == "join":
                need(list, "cannot be iterated over")
                return [sep.join("" if v is None else v if isinstance(v, str) else dumps(v, compact=True) for v in value)
                        for sep in one()]
            if name in ("ltrimstr", "rtrimstr"):
                out = []
                for text in one():
                    if isinstance(value, str) and isinstance(text, str):
                        if name == "ltrimstr" and value.startswith(text):
                            out.append(value[len(text):])
                            continue
                        if name == "rtrimstr" and value.endswith(text) and text:
                            out.append(value[:-len(text)])
                            continue
                    out.append(value)
                return out
            need(str, f"cannot be {'split' if name == 'split' else 'used'}, as it is not a string")
            if name == "ascii_downcase":
                return [value.lower()]
            if name == "ascii_upcase":
                return [value.upper()]
            if name in ("ltrim", "rtrim", "trim"):
                return [{"ltrim": value.lstrip, "rtrim": value.rstrip, "trim": value.strip}[name]()]
            if name == "split":
                return [value.split(sep) for sep in one()]
            return [getattr(value, name)(text) for text in one()]
        if name == "tostring":
            return [value if isinstance(value, str) else dumps(value, compact=True)]
        if name == "tonumber":
            if isinstance(value, (int, float)):
                return [value]
            try:
                return [normalise_number(float(value))]
            except (TypeError, ValueError):
                raise JqError(f"jq: error: Cannot parse '{value}' as JSON") from None
        if name == "tojson":
            return [dumps(value, compact=True)]
        if name == "fromjson":
            return [json.loads(value)]
        if name == "type":
            return [type_name(value)]
        if name == "range":
            bounds = [one(i)[0] for i in range(len(args))]
            return list(range(*[int(b) for b in bounds]))
        if name == "limit":
            count = int(one(0)[0])
            return self.eval(args[1], value, env)[:count]
        if name == "error":
            raise JqError(f"jq: error: {one()[0] if args else value}")
        if name == "input_filename":
            return [None]
        if name in ("ascii", "now", "todate", "fromdate", "strftime", "splits", "sub", "gsub", "paths", "path",
                    "getpath", "setpath", "del", "to_number", "env", "input", "inputs", "debug", "stderr",
                    "walk", "indices", "index", "rindex", "inside", "combinations", "ascii", "implode", "explode",
                    "tostream", "fromstream", "truncate_stream", "getpath", "splits", "ltrimstr", "isvalid"):
            raise Unsupported(f"jq: '{name}' is not supported in the simulated terminal")
        raise JqError(f"jq: error: {name}/{len(args)} is not defined")


def truthy(value) -> bool:
    return value is not None and value is not False


def contains(a, b) -> bool:
    if isinstance(a, dict) and isinstance(b, dict):
        return all(k in a and contains(a[k], v) for k, v in b.items())
    if isinstance(a, list) and isinstance(b, list):
        return all(any(contains(x, y) for x in a) for y in b)
    if isinstance(a, str) and isinstance(b, str):
        return b in a
    if type_name(a) != type_name(b):
        raise JqError(f"jq: error: {describe(a)} and {describe(b)} cannot have their containment checked")
    return a == b


def dumps(value, compact: bool = False, sort_keys: bool = False) -> str:
    if compact:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=sort_keys)
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=sort_keys)


def run_jq(program: str, documents: list, raw: bool = False, compact: bool = False, sort_keys: bool = False,
           join: bool = False, variables: dict | None = None) -> str:
    jq = Jq(program, variables)
    lines = []
    for document in documents:
        for value in jq.run(document):
            if raw and isinstance(value, str):
                lines.append(value)
            else:
                lines.append(dumps(value, compact=compact, sort_keys=sort_keys))
    return ("" if join else "\n").join(lines) + ("" if join or not lines else "\n")
