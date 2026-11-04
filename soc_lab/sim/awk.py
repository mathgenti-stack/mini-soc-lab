"""A small awk for the simulated bash: the part of the language analysts use on logs.

Supported: patterns (expressions, /regex/, BEGIN, END), print and printf, fields ($1, $NF, $(NF-3)),
NR, NF, FS, OFS, FILENAME, variables, arrays with `for (k in a)`, if/else, while, for, next, exit,
the operators of awk (including ~ !~ in ++ += and string concatenation) and the functions length,
substr, index, split, sub, gsub, match, tolower, toupper, sprintf and int. Not supported: getline,
user-defined functions and output redirection.
"""

from __future__ import annotations

import math
import re

from .core import ShellError, Unsupported
from .regex import compile_posix


class AwkError(ShellError):
    pass


class StrNum(str):
    """A value read from input: a string that compares as a number when it looks like one."""


UNINIT = StrNum("")
NUMBER = re.compile(r"^\s*[-+]?(\d+\.?\d*([eE][-+]?\d+)?|\.\d+([eE][-+]?\d+)?)\s*$")
LEADING_NUMBER = re.compile(r"^\s*[-+]?(\d+\.?\d*([eE][-+]?\d+)?|\.\d+([eE][-+]?\d+)?)")


# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------
KEYWORDS = {"BEGIN", "END", "print", "printf", "if", "else", "while", "for", "in", "next", "exit", "delete",
            "getline", "function", "return", "do", "break", "continue"}
BUILTINS = {"length", "substr", "index", "split", "sub", "gsub", "match", "tolower", "toupper", "sprintf", "int",
            "sqrt", "log", "exp", "sin", "cos", "rand", "srand", "systime"}
OPERATORS = ["+=", "-=", "*=", "/=", "%=", "^=", "==", "<=", ">=", "!=", "++", "--", "&&", "||", "!~",
             "{", "}", "(", ")", "[", "]", ";", ",", "+", "-", "*", "/", "%", "^", "!", ">", "<", "|", "?", ":",
             "~", "$", "="]


def tokenize(source: str) -> list[tuple[str, object]]:
    tokens: list[tuple[str, object]] = []
    i = 0
    n = len(source)

    def regex_allowed() -> bool:
        if not tokens:
            return True
        kind, value = tokens[-1]
        if kind in ("number", "string", "name", "builtin", "regex"):
            return False
        return value not in (")", "]", "$", "++", "--")

    while i < n:
        ch = source[i]
        if ch in " \t\r":
            i += 1
        elif ch == "\\" and i + 1 < n and source[i + 1] == "\n":
            i += 2
        elif ch == "\n":
            tokens.append(("newline", "\n"))
            i += 1
        elif ch == "#":
            while i < n and source[i] != "\n":
                i += 1
        elif ch == '"':
            i += 1
            buf = []
            while i < n and source[i] != '"':
                if source[i] == "\\" and i + 1 < n:
                    esc = source[i + 1]
                    buf.append({"n": "\n", "t": "\t", "\\": "\\", '"': '"', "/": "/", "r": "\r"}.get(esc, "\\" + esc))
                    i += 2
                else:
                    buf.append(source[i])
                    i += 1
            if i >= n:
                raise AwkError("awk: unterminated string")
            tokens.append(("string", "".join(buf)))
            i += 1
        elif ch == "/" and regex_allowed():
            i += 1
            buf = []
            while i < n and source[i] != "/":
                if source[i] == "\\" and i + 1 < n:
                    buf.append(source[i:i + 2])
                    i += 2
                else:
                    buf.append(source[i])
                    i += 1
            if i >= n:
                raise AwkError("awk: unterminated regexp")
            tokens.append(("regex", "".join(buf).replace("\\/", "/")))
            i += 1
        elif ch.isdigit() or (ch == "." and i + 1 < n and source[i + 1].isdigit()):
            match = re.match(r"\d*\.?\d*([eE][-+]?\d+)?", source[i:])
            text = match.group(0)
            tokens.append(("number", float(text)))
            i += len(text)
        elif ch.isalpha() or ch == "_":
            match = re.match(r"[A-Za-z_]\w*", source[i:])
            word = match.group(0)
            i += len(word)
            kind = "keyword" if word in KEYWORDS else "builtin" if word in BUILTINS else "name"
            tokens.append((kind, word))
        else:
            for op in OPERATORS:
                if source.startswith(op, i):
                    tokens.append(("op", op))
                    i += len(op)
                    break
            else:
                raise AwkError(f"awk: syntax error at source line 1: unexpected character '{ch}'")
    tokens.append(("eof", None))
    return tokens


# ---------------------------------------------------------------------------
# Parser -> nested tuples
# ---------------------------------------------------------------------------
class Parser:
    def __init__(self, source: str):
        self.tokens = tokenize(source)
        self.pos = 0

    def peek(self, offset: int = 0):
        return self.tokens[min(self.pos + offset, len(self.tokens) - 1)]

    def take(self):
        token = self.tokens[self.pos]
        self.pos += 1
        return token

    def at(self, kind: str, value=None) -> bool:
        tk, tv = self.peek()
        return tk == kind and (value is None or tv == value)

    def at_op(self, *values) -> bool:
        tk, tv = self.peek()
        return tk == "op" and tv in values

    def expect_op(self, value: str):
        if not self.at_op(value):
            raise AwkError(f"awk: syntax error: expected '{value}' near {self.describe()}")
        return self.take()

    def describe(self) -> str:
        kind, value = self.peek()
        return "end of program" if kind == "eof" else repr(value)

    def skip_newlines(self):
        while self.at("newline") or self.at_op(";"):
            self.take()

    def skip_nl_only(self):
        while self.at("newline"):
            self.take()

    # program -----------------------------------------------------------
    def program(self):
        items = []
        self.skip_newlines()
        while not self.at("eof"):
            if self.at("keyword", "function"):
                raise Unsupported("awk: user-defined functions are not supported in the simulated terminal")
            if self.at("keyword", "BEGIN") or self.at("keyword", "END"):
                kind = self.take()[1]
                self.skip_nl_only()
                items.append((kind, None, self.block()))
            else:
                pattern = None if self.at_op("{") else self.expression()
                if self.at_op(","):
                    raise Unsupported("awk: range patterns (a,b) are not supported in the simulated terminal")
                action = self.block() if self.at_op("{") else None
                items.append(("main", pattern, action))
            self.skip_newlines()
        return items

    def block(self):
        self.expect_op("{")
        statements = []
        self.skip_newlines()
        while not self.at_op("}"):
            if self.at("eof"):
                raise AwkError("awk: syntax error: missing }")
            statements.append(self.statement())
            self.skip_newlines()
        self.take()
        return ("block", statements)

    def simple_end(self):
        if self.at_op(";") or self.at("newline"):
            self.take()

    def statement(self):
        if self.at_op("{"):
            return self.block()
        kind, value = self.peek()
        if kind == "keyword":
            if value in ("print", "printf"):
                self.take()
                args = []
                parens = False
                if self.at_op("(") and self._paren_list_ahead():
                    self.take()
                    parens = True
                if not (self.at_op(";", "}") or self.at("newline") or self.at("eof")):
                    args.append(self.expression(no_gt=not parens))
                    while self.at_op(","):
                        self.take()
                        self.skip_nl_only()
                        args.append(self.expression(no_gt=not parens))
                if parens:
                    self.expect_op(")")
                if self.at_op(">", "|") or self.at_op(">>"):
                    raise Unsupported("awk: output redirection is not supported in the simulated terminal")
                self.simple_end()
                return (value, args)
            if value == "if":
                self.take()
                self.expect_op("(")
                cond = self.expression()
                self.expect_op(")")
                self.skip_nl_only()
                then = self.statement()
                save = self.pos
                self.skip_newlines()
                if self.at("keyword", "else"):
                    self.take()
                    self.skip_nl_only()
                    return ("if", cond, then, self.statement())
                self.pos = save
                return ("if", cond, then, None)
            if value == "while":
                self.take()
                self.expect_op("(")
                cond = self.expression()
                self.expect_op(")")
                self.skip_nl_only()
                return ("while", cond, self.statement())
            if value == "for":
                self.take()
                self.expect_op("(")
                if self.peek()[0] == "name" and self.peek(1) == ("keyword", "in"):
                    var = self.take()[1]
                    self.take()
                    array = self.take()[1]
                    self.expect_op(")")
                    self.skip_nl_only()
                    return ("forin", var, array, self.statement())
                init = None if self.at_op(";") else self.expression()
                self.expect_op(";")
                cond = None if self.at_op(";") else self.expression()
                self.expect_op(";")
                step = None if self.at_op(")") else self.expression()
                self.expect_op(")")
                self.skip_nl_only()
                return ("for", init, cond, step, self.statement())
            if value in ("next", "exit", "break", "continue"):
                self.take()
                code = None
                if value == "exit" and not (self.at_op(";", "}") or self.at("newline") or self.at("eof")):
                    code = self.expression()
                self.simple_end()
                return (value, code)
            if value == "delete":
                self.take()
                name = self.take()[1]
                index = None
                if self.at_op("["):
                    self.take()
                    index = self.expr_list_until("]")
                self.simple_end()
                return ("delete", name, index)
            if value in ("getline", "do", "return"):
                raise Unsupported(f"awk: '{value}' is not supported in the simulated terminal")
        expr = self.expression()
        self.simple_end()
        return ("expr", expr)

    def _paren_list_ahead(self) -> bool:
        """print (a, b) vs print (a) b: only treat as a list if the matching ) ends the statement."""
        depth = 0
        i = self.pos
        while i < len(self.tokens):
            kind, value = self.tokens[i]
            if kind == "op" and value in ("(", "["):
                depth += 1
            elif kind == "op" and value in (")", "]"):
                depth -= 1
                if depth == 0:
                    nxt = self.tokens[i + 1]
                    return nxt[0] in ("newline", "eof") or (nxt[0] == "op" and nxt[1] in (";", "}", ">", "|"))
            i += 1
        return False

    def expr_list_until(self, closing: str):
        items = [self.expression()]
        while self.at_op(","):
            self.take()
            items.append(self.expression())
        self.expect_op(closing)
        return items

    # expressions ---------------------------------------------------------
    def expression(self, no_gt: bool = False):
        self.no_gt = no_gt
        return self.ternary()

    def ternary(self):
        cond = self.or_expr()
        if self.at_op("?"):
            self.take()
            self.skip_nl_only()
            a = self.ternary()
            self.skip_nl_only()
            self.expect_op(":")
            self.skip_nl_only()
            b = self.ternary()
            return ("?:", cond, a, b)
        if self.at_op("=", "+=", "-=", "*=", "/=", "%=", "^="):
            if cond[0] not in ("var", "field", "index"):
                raise AwkError("awk: syntax error: assignment to a non-variable")
            op = self.take()[1]
            self.skip_nl_only()
            return ("assign", op, cond, self.ternary())
        return cond

    def or_expr(self):
        left = self.and_expr()
        while self.at_op("||"):
            self.take()
            self.skip_nl_only()
            left = ("||", left, self.and_expr())
        return left

    def and_expr(self):
        left = self.in_expr()
        while self.at_op("&&"):
            self.take()
            self.skip_nl_only()
            left = ("&&", left, self.in_expr())
        return left

    def in_expr(self):
        left = self.match_expr()
        while self.at("keyword", "in"):
            self.take()
            left = ("in", left, self.take()[1])
        return left

    def match_expr(self):
        left = self.compare()
        while self.at_op("~", "!~"):
            op = self.take()[1]
            left = (op, left, self.compare())
        return left

    def compare(self):
        left = self.concat()
        ops = ("<", "<=", "!=", "==", ">=") if self.no_gt else ("<", "<=", "!=", "==", ">", ">=")
        if self.at_op(*ops):
            op = self.take()[1]
            left = ("cmp", op, left, self.concat())
        return left

    def starts_operand(self) -> bool:
        kind, value = self.peek()
        if kind in ("number", "string", "regex", "name", "builtin"):
            return True
        return kind == "op" and value in ("$", "(", "!", "-", "+", "++", "--")

    def concat(self):
        left = self.additive()
        while self.starts_operand() and not self.at_op("-", "+"):
            left = ("concat", left, self.additive())
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
        if self.at_op("!"):
            self.take()
            return ("not", self.unary())
        if self.at_op("-"):
            self.take()
            return ("neg", self.unary())
        if self.at_op("+"):
            self.take()
            return ("num", self.unary())
        return self.power()

    def power(self):
        base = self.postfix()
        if self.at_op("^"):
            self.take()
            return ("arith", "^", base, self.unary())
        return base

    def postfix(self):
        if self.at_op("++", "--"):
            op = self.take()[1]
            target = self.postfix()
            return ("preinc", op, target)
        node = self.primary()
        if self.at_op("++", "--") and node[0] in ("var", "field", "index"):
            return ("postinc", self.take()[1], node)
        return node

    def primary(self):
        kind, value = self.take()
        if kind == "number":
            return ("const", value)
        if kind == "string":
            return ("const", value)
        if kind == "regex":
            return ("regex", value)
        if kind == "op" and value == "$":
            return ("field", self.primary_for_field())
        if kind == "op" and value == "(":
            first = self.expression()
            if self.at_op(","):  # (a, b) in array
                items = [first]
                while self.at_op(","):
                    self.take()
                    items.append(self.expression())
                self.expect_op(")")
                if not self.at("keyword", "in"):
                    raise AwkError("awk: syntax error near ,")
                self.take()
                return ("in", ("group", items), self.take()[1])
            self.expect_op(")")
            return ("group", [first])
        if kind == "builtin":
            args = []
            if self.at_op("("):
                self.take()
                if not self.at_op(")"):
                    args = self.expr_list_until(")")
                else:
                    self.take()
            elif value != "length":
                raise AwkError(f"awk: syntax error: {value} needs (")
            return ("call", value, args)
        if kind == "name":
            if self.at_op("["):
                self.take()
                return ("index", value, self.expr_list_until("]"))
            return ("var", value)
        if kind == "op" and value in ("-", "!"):
            return ("neg", self.primary()) if value == "-" else ("not", self.primary())
        raise AwkError(f"awk: syntax error near {value!r}" if kind != "eof" else "awk: syntax error: unexpected end")

    def primary_for_field(self):
        if self.at_op("("):
            return self.primary()
        if self.at_op("++", "--"):
            return self.postfix()
        kind, value = self.take()
        if kind == "number":
            return ("const", value)
        if kind == "name":
            if self.at_op("["):
                self.take()
                return ("index", value, self.expr_list_until("]"))
            return ("var", value)
        if kind == "op" and value == "$":
            return ("field", self.primary_for_field())
        raise AwkError("awk: syntax error after $")


# ---------------------------------------------------------------------------
# Interpreter
# ---------------------------------------------------------------------------
class _Next(Exception):
    pass


class _Exit(Exception):
    pass


class _Break(Exception):
    pass


class _Continue(Exception):
    pass


def to_num(value) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    match = LEADING_NUMBER.match(value or "")
    return float(match.group(0)) if match else 0.0


def looks_numeric(value) -> bool:
    if isinstance(value, (int, float)):
        return True
    if value is UNINIT:
        return True
    return isinstance(value, StrNum) and bool(NUMBER.match(value))


def fmt_num(value: float, ofmt: str = "%.6g") -> str:
    if value == int(value) and abs(value) < 1e16:
        return str(int(value))
    return ofmt % value


def to_str(value) -> str:
    if isinstance(value, float):
        return fmt_num(value)
    if isinstance(value, int):
        return str(value)
    return value


def truthy(value) -> bool:
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, StrNum) and looks_numeric(value) and value is not UNINIT:
        return to_num(value) != 0
    return value != ""


def awk_sprintf(fmt: str, args: list) -> str:
    out = []
    i = 0
    arg_index = 0
    spec = re.compile(r"%([-+ #0]*)(\*|\d+)?(?:\.(\*|\d+))?([diouxXeEfgGcs%])")
    while i < len(fmt):
        match = spec.match(fmt, i)
        if fmt[i] == "%" and match:
            flags, width, precision, conv = match.groups()
            i = match.end()
            if conv == "%":
                out.append("%")
                continue
            if width == "*":
                width = str(int(to_num(args[arg_index]))) if arg_index < len(args) else ""
                arg_index += 1
            if precision == "*":
                precision = str(int(to_num(args[arg_index]))) if arg_index < len(args) else ""
                arg_index += 1
            value = args[arg_index] if arg_index < len(args) else UNINIT
            arg_index += 1
            python = "%" + flags + (width or "") + (f".{precision}" if precision is not None else "")
            if conv in "diouxX":
                conv = "d" if conv in "iu" else conv
                out.append((python + conv) % int(to_num(value)))
            elif conv in "eEfgG":
                out.append((python + conv) % to_num(value))
            elif conv == "c":
                text = chr(int(to_num(value))) if isinstance(value, (int, float)) else to_str(value)[:1]
                out.append((python + "s") % text)
            else:
                out.append((python + "s") % to_str(value))
        else:
            out.append(fmt[i])
            i += 1
    return "".join(out)


class Awk:
    def __init__(self, program: str, field_sep: str | None = None, assignments: dict | None = None):
        self.items = Parser(program).program()
        self.vars: dict[str, object] = {"FS": " ", "OFS": " ", "ORS": "\n", "NR": 0.0, "NF": 0.0, "FNR": 0.0,
                                        "FILENAME": "", "SUBSEP": "\x1c", "RSTART": 0.0, "RLENGTH": -1.0}
        if field_sep is not None:
            self.vars["FS"] = "\t" if field_sep == "t" else field_sep
        for name, value in (assignments or {}).items():
            self.vars[name] = StrNum(value)
        self.arrays: dict[str, dict] = {}
        self.out: list[str] = []
        self.fields: list[str] = []
        self.record = ""
        self.exit_code = 0
        self._regex_cache: dict[str, re.Pattern] = {}

    # records -------------------------------------------------------------
    def set_record(self, line: str):
        self.record = line
        self.fields = self.split(line, to_str(self.vars["FS"]))
        self.vars["NF"] = float(len(self.fields))

    def split(self, text: str, sep: str) -> list[str]:
        if sep == " ":
            return text.split()
        if len(sep) == 1 and sep != "\\":
            return text.split(sep) if text else []
        if not text:
            return []
        return self.regex(sep).split(text)

    def regex(self, pattern: str) -> re.Pattern:
        if pattern not in self._regex_cache:
            self._regex_cache[pattern] = compile_posix(pattern, extended=True)
        return self._regex_cache[pattern]

    def get_field(self, index: int):
        if index < 0:
            raise AwkError(f"awk: trying to access out of range field {index}")
        if index == 0:
            return StrNum(self.record)
        return StrNum(self.fields[index - 1]) if index <= len(self.fields) else UNINIT

    def set_field(self, index: int, value):
        if index == 0:
            self.set_record(to_str(value))
            return
        while len(self.fields) < index:
            self.fields.append("")
        self.fields[index - 1] = to_str(value)
        self.vars["NF"] = float(len(self.fields))
        self.record = to_str(self.vars["OFS"]).join(self.fields)

    # running -------------------------------------------------------------
    def run(self, inputs: list[tuple[str, str]]) -> str:
        """inputs: [(file name, text)]."""
        try:
            for kind, _, action in self.items:
                if kind == "BEGIN":
                    self.exec(action)
            main = [(p, a) for k, p, a in self.items if k == "main"]
            if main or any(k == "END" for k, _, _ in self.items):
                for name, text in inputs:
                    self.vars["FILENAME"] = name
                    self.vars["FNR"] = 0.0
                    lines = text.split("\n")
                    if lines and lines[-1] == "":
                        lines.pop()
                    for line in lines:
                        self.vars["NR"] = to_num(self.vars["NR"]) + 1
                        self.vars["FNR"] = to_num(self.vars["FNR"]) + 1
                        self.set_record(line)
                        try:
                            for pattern, action in main:
                                if pattern is None or truthy(self.match_pattern(pattern)):
                                    if action is None:
                                        self.emit(self.record)
                                    else:
                                        self.exec(action)
                        except _Next:
                            continue
            for kind, _, action in self.items:
                if kind == "END":
                    self.exec(action)
        except _Exit:
            for kind, _, action in self.items:
                if kind == "END" and not getattr(self, "_in_end", False):
                    self._in_end = True
                    try:
                        self.exec(action)
                    except _Exit:
                        pass
        return "".join(self.out)

    def match_pattern(self, pattern):
        if pattern[0] == "regex":
            return 1.0 if self.regex(pattern[1]).search(self.record) else 0.0
        return self.eval(pattern)

    def emit(self, text: str):
        self.out.append(text + to_str(self.vars["ORS"]))
        if len(self.out) > 200000:
            raise AwkError("awk: output too long for the simulated terminal")

    def exec(self, node):
        kind = node[0]
        if kind == "block":
            for statement in node[1]:
                self.exec(statement)
        elif kind == "print":
            values = [to_str(self.eval(arg)) for arg in node[1]] if node[1] else [self.record]
            if node[1] and len(node[1]) == 1 and node[1][0][0] == "group" and len(node[1][0][1]) > 1:
                values = [to_str(self.eval(arg)) for arg in node[1][0][1]]
            self.emit(to_str(self.vars["OFS"]).join(
                fmt_num(v, to_str(self.vars.get("OFMT", "%.6g"))) if isinstance(v, float) else v for v in values))
        elif kind == "printf":
            if not node[1]:
                raise AwkError("awk: printf: no format")
            args = [self.eval(arg) for arg in node[1]]
            self.out.append(awk_sprintf(to_str(args[0]), args[1:]))
        elif kind == "expr":
            self.eval(node[1])
        elif kind == "if":
            if truthy(self.eval(node[1])):
                self.exec(node[2])
            elif node[3] is not None:
                self.exec(node[3])
        elif kind == "while":
            guard = 0
            while truthy(self.eval(node[1])):
                guard += 1
                if guard > 1_000_000:
                    raise AwkError("awk: loop stopped after a million turns")
                try:
                    self.exec(node[2])
                except _Break:
                    break
                except _Continue:
                    continue
        elif kind == "for":
            _, init, cond, step, body = node
            if init is not None:
                self.eval(init)
            guard = 0
            while cond is None or truthy(self.eval(cond)):
                guard += 1
                if guard > 1_000_000:
                    raise AwkError("awk: loop stopped after a million turns")
                try:
                    self.exec(body)
                except _Break:
                    break
                except _Continue:
                    pass
                if step is not None:
                    self.eval(step)
        elif kind == "forin":
            _, var, array, body = node
            for key in list(self.arrays.get(array, {})):
                self.vars[var] = StrNum(key)
                try:
                    self.exec(body)
                except _Break:
                    break
                except _Continue:
                    continue
        elif kind == "next":
            raise _Next()
        elif kind == "exit":
            if node[1] is not None:
                self.exit_code = int(to_num(self.eval(node[1])))
            raise _Exit()
        elif kind == "break":
            raise _Break()
        elif kind == "continue":
            raise _Continue()
        elif kind == "delete":
            _, name, index = node
            if index is None:
                self.arrays[name] = {}
            else:
                self.arrays.setdefault(name, {}).pop(self.key(index), None)
        else:
            raise AwkError(f"awk: cannot run {kind}")

    def key(self, index_nodes) -> str:
        return to_str(self.vars["SUBSEP"]).join(to_str(self.eval(n)) for n in index_nodes)

    def lvalue_get(self, node):
        kind = node[0]
        if kind == "var":
            if node[1] in self.arrays:
                raise AwkError(f"awk: can't use array {node[1]} in scalar context")
            return self.vars.get(node[1], UNINIT)
        if kind == "field":
            return self.get_field(int(to_num(self.eval(node[1]))))
        if kind == "index":
            return self.arrays.setdefault(node[1], {}).get(self.key(node[2]), UNINIT)
        raise AwkError("awk: assignment to a non-variable")

    def lvalue_set(self, node, value):
        kind = node[0]
        if kind == "var":
            self.vars[node[1]] = value
            if node[1] == "NF":
                count = int(to_num(value))
                self.fields = (self.fields + [""] * count)[:count]
                self.record = to_str(self.vars["OFS"]).join(self.fields)
        elif kind == "field":
            self.set_field(int(to_num(self.eval(node[1]))), value)
        elif kind == "index":
            self.arrays.setdefault(node[1], {})[self.key(node[2])] = value
        return value

    def eval(self, node):
        kind = node[0]
        if kind == "const":
            return node[1]
        if kind == "regex":
            return 1.0 if self.regex(node[1]).search(self.record) else 0.0
        if kind == "group":
            return self.eval(node[1][-1])
        if kind in ("var", "field", "index"):
            return self.lvalue_get(node)
        if kind == "assign":
            _, op, target, expr = node
            value = self.eval(expr)
            if op != "=":
                value = self.arith(op[0], self.lvalue_get(target), value)
            elif isinstance(value, StrNum) and value is not UNINIT:
                value = StrNum(value)
            return self.lvalue_set(target, value)
        if kind == "preinc":
            value = to_num(self.lvalue_get(node[2])) + (1 if node[1] == "++" else -1)
            return self.lvalue_set(node[2], value)
        if kind == "postinc":
            old = to_num(self.lvalue_get(node[2]))
            self.lvalue_set(node[2], old + (1 if node[1] == "++" else -1))
            return old
        if kind == "arith":
            return self.arith(node[1], self.eval(node[2]), self.eval(node[3]))
        if kind == "neg":
            return -to_num(self.eval(node[1]))
        if kind == "num":
            return to_num(self.eval(node[1]))
        if kind == "not":
            return 0.0 if truthy(self.eval(node[1])) else 1.0
        if kind == "&&":
            return 1.0 if truthy(self.eval(node[1])) and truthy(self.eval(node[2])) else 0.0
        if kind == "||":
            return 1.0 if truthy(self.eval(node[1])) or truthy(self.eval(node[2])) else 0.0
        if kind == "?:":
            return self.eval(node[2]) if truthy(self.eval(node[1])) else self.eval(node[3])
        if kind == "concat":
            return to_str(self.eval(node[1])) + to_str(self.eval(node[2]))
        if kind in ("~", "!~"):
            text = to_str(self.eval(node[1]))
            right = node[2]
            pattern = right[1] if right[0] == "regex" else to_str(self.eval(right))
            found = bool(self.regex(pattern).search(text))
            return 1.0 if found == (kind == "~") else 0.0
        if kind == "cmp":
            return 1.0 if self.compare(node[1], self.eval(node[2]), self.eval(node[3])) else 0.0
        if kind == "in":
            key = self.key(node[1][1]) if node[1][0] == "group" else to_str(self.eval(node[1]))
            return 1.0 if key in self.arrays.get(node[2], {}) else 0.0
        if kind == "call":
            return self.call(node[1], node[2])
        raise AwkError(f"awk: cannot evaluate {kind}")

    def arith(self, op: str, a, b) -> float:
        x, y = to_num(a), to_num(b)
        if op == "+":
            return x + y
        if op == "-":
            return x - y
        if op == "*":
            return x * y
        if op in "/%":
            if y == 0:
                raise AwkError("awk: division by zero" + (" in %" if op == "%" else ""))
            return x / y if op == "/" else math.fmod(x, y)
        if op == "^":
            return x ** y
        raise AwkError(f"awk: unknown operator {op}")

    @staticmethod
    def compare(op: str, a, b) -> bool:
        if looks_numeric(a) and looks_numeric(b):
            x, y = to_num(a), to_num(b)
        else:
            x, y = to_str(a), to_str(b)
        return {"<": x < y, "<=": x <= y, "==": x == y, "!=": x != y, ">": x > y, ">=": x >= y}[op]

    def call(self, name: str, args: list):
        def arg(i, default=None):
            return self.eval(args[i]) if i < len(args) else default

        if name == "length":
            if args and args[0][0] == "var" and args[0][1] in self.arrays:
                return float(len(self.arrays[args[0][1]]))
            return float(len(to_str(arg(0, self.record))))
        if name == "substr":
            text = to_str(arg(0, ""))
            start = round(to_num(arg(1, 1)))
            length = round(to_num(arg(2))) if len(args) > 2 else len(text) + 1
            begin = max(start, 1)
            end = start + length
            return text[begin - 1:max(end - 1, begin - 1)]
        if name == "index":
            return float(to_str(arg(0, "")).find(to_str(arg(1, ""))) + 1)
        if name == "split":
            text = to_str(arg(0, ""))
            target = args[1][1]
            sep = (args[2][1] if args[2][0] == "regex" else to_str(self.eval(args[2]))) if len(args) > 2 else to_str(self.vars["FS"])
            parts = self.split(text, sep)
            self.arrays[target] = {str(i + 1): StrNum(p) for i, p in enumerate(parts)}
            return float(len(parts))
        if name in ("sub", "gsub"):
            pattern = args[0][1] if args[0][0] == "regex" else to_str(self.eval(args[0]))
            replacement = to_str(arg(1, ""))
            target = args[2] if len(args) > 2 else ("field", ("const", 0.0))
            text = to_str(self.lvalue_get(target))
            python_repl = replacement.replace("\\&", "\x00").replace("&", r"\g<0>").replace("\x00", "&")
            python_repl = re.sub(r"\\(?![g\\])", r"\\\\", python_repl)
            new, count = self.regex(pattern).subn(python_repl, text, count=1 if name == "sub" else 0)
            if count:
                self.lvalue_set(target, StrNum(new))
            return float(count)
        if name == "match":
            text = to_str(arg(0, ""))
            pattern = args[1][1] if args[1][0] == "regex" else to_str(self.eval(args[1]))
            found = self.regex(pattern).search(text)
            self.vars["RSTART"] = float(found.start() + 1) if found else 0.0
            self.vars["RLENGTH"] = float(found.end() - found.start()) if found else -1.0
            return self.vars["RSTART"]
        if name == "tolower":
            return to_str(arg(0, "")).lower()
        if name == "toupper":
            return to_str(arg(0, "")).upper()
        if name == "sprintf":
            values = [self.eval(a) for a in args]
            return awk_sprintf(to_str(values[0]), values[1:]) if values else ""
        if name == "int":
            return float(int(to_num(arg(0, 0))))
        if name == "sqrt":
            return math.sqrt(to_num(arg(0, 0)))
        if name == "log":
            return math.log(to_num(arg(0, 1)))
        if name == "exp":
            return math.exp(to_num(arg(0, 0)))
        if name in ("sin", "cos"):
            return getattr(math, name)(to_num(arg(0, 0)))
        if name == "rand":
            return 0.237788
        if name in ("srand", "systime"):
            return 0.0
        raise Unsupported(f"awk: function {name} is not supported in the simulated terminal")


def run_awk(program: str, inputs: list[tuple[str, str]], field_sep: str | None = None,
            assignments: dict | None = None) -> str:
    return Awk(program, field_sep, assignments).run(inputs)
