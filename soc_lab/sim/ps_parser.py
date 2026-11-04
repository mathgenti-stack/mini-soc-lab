"""Parser of the simulated PowerShell: statements, pipelines, commands and expressions -> nested tuples.

PowerShell reads a line in two modes. At the start of a pipeline element, a word is a command
(Get-ChildItem, ls, Where-Object) and what follows are its arguments: -Parameters and values, where
a bare word such as logs/sample_auth_logs.csv is a string. Anything starting with $ ( @ ' " [ or a
number is an expression, with operators such as -eq, -and, + and member access ($_.Name).
"""

from __future__ import annotations

import re

from .core import ShellError, Unsupported


class PSParseError(ShellError):
    pass


END = "\0"


COMPARISON = {
    "eq", "ne", "gt", "ge", "lt", "le", "like", "notlike", "match", "notmatch", "contains", "notcontains",
    "in", "notin", "replace", "split", "join", "is", "isnot", "as",
}
CASED = {p + op for op in ("eq", "ne", "gt", "ge", "lt", "le", "like", "notlike", "match", "notmatch", "contains",
                           "notcontains", "in", "notin", "replace", "split") for p in ("i", "c")}
LOGICAL = {"and", "or", "xor"}
BITWISE = {"band", "bor", "bxor"}
KEYWORDS = {"if", "elseif", "else", "foreach", "for", "while", "do", "break", "continue", "return", "function",
            "filter", "switch", "try", "catch", "finally", "throw", "param", "begin", "process", "end", "trap",
            "until", "in", "class", "enum", "exit"}
ARG_END = set(" \t\r\n|;)},")
NUMBER = re.compile(r"(0x[0-9a-fA-F]+|\d+(?:\.\d+)?(?:[eE][-+]?\d+)?|\.\d+(?:[eE][-+]?\d+)?)(kb|mb|gb|tb|pb|l|d)?",
                    re.IGNORECASE)
SIMPLE_VARIABLE = re.compile(r"\$(?:[A-Za-z_][\w]*:)?[A-Za-z_?^$][\w]*")


def number_value(text: str, suffix: str | None):
    text_lower = text.lower()
    value = int(text_lower, 16) if text_lower.startswith("0x") else (
        float(text) if any(c in text_lower for c in ".e") else int(text))
    multiplier = {"kb": 1024, "mb": 1024 ** 2, "gb": 1024 ** 3, "tb": 1024 ** 4, "pb": 1024 ** 5}.get(
        (suffix or "").lower(), 1)
    return value * multiplier


class Parser:
    def __init__(self, source: str):
        self.src = source
        self.pos = 0
        self.no_comma = False  # inside method arguments, commas separate arguments

    # low-level -----------------------------------------------------------------
    def error(self, message: str):
        raise PSParseError(f"ParserError: {message}")

    def peek(self, offset: int = 0) -> str:
        i = self.pos + offset
        return self.src[i] if i < len(self.src) else END  # END is in none of the character sets tested below

    def starts(self, text: str) -> bool:
        return self.src.startswith(text, self.pos)

    def at_end(self) -> bool:
        return self.pos >= len(self.src)

    def skip_ws(self):
        while not self.at_end():
            ch = self.peek()
            if ch in " \t\r":
                self.pos += 1
            elif ch == "`" and self.peek(1) == "\n":
                self.pos += 2
            elif ch == "<" and self.peek(1) == "#":
                end = self.src.find("#>", self.pos)
                self.pos = len(self.src) if end == -1 else end + 2
            elif ch == "#":
                while not self.at_end() and self.peek() != "\n":
                    self.pos += 1
            else:
                break

    def skip_ws_nl(self):
        while True:
            self.skip_ws()
            if self.peek() == "\n":
                self.pos += 1
            else:
                break

    def word_at(self) -> str:
        match = re.compile(r"[A-Za-z_][\w-]*").match(self.src, self.pos)
        return match.group(0) if match else ""

    def keyword_at(self) -> str:
        match = re.compile(r"([A-Za-z]+)(?=[\s({;]|$)").match(self.src, self.pos)
        word = match.group(1).lower() if match else ""
        return word if word in KEYWORDS else ""

    def expect(self, text: str):
        self.skip_ws()
        if not self.starts(text):
            found = self.src[self.pos:self.pos + 10] or "end of line"
            self.error(f"Missing '{text}' (found '{found}').")
        self.pos += len(text)

    # statements ------------------------------------------------------------------
    def parse(self):
        script = self.statements(terminator="")
        self.skip_ws_nl()
        if not self.at_end():
            self.error(f"Unexpected token '{self.src[self.pos:self.pos + 20]}' in expression or statement.")
        return script

    def statements(self, terminator: str):
        saved, self.no_comma = self.no_comma, False
        try:
            return self._statements(terminator)
        finally:
            self.no_comma = saved

    def _statements(self, terminator: str):
        items = []
        while True:
            self.skip_ws_nl()
            while self.peek() == ";":
                self.pos += 1
                self.skip_ws_nl()
            if self.at_end() or (terminator and self.peek() == terminator):
                break
            items.append(self.statement())
            self.skip_ws()
            if self.peek() in (";", "\n"):
                self.pos += 1
            elif self.at_end() or (terminator and self.peek() == terminator):
                break
            else:
                self.error(f"Unexpected token '{self.src[self.pos:self.pos + 20]}' in expression or statement.")
        return ("script", items)

    def block(self):
        self.skip_ws_nl()
        self.expect("{")
        body = self.statements("}")
        self.expect("}")
        return body

    def condition(self):
        self.skip_ws()
        self.expect("(")
        self.skip_ws_nl()
        node = self.pipeline()
        self.skip_ws_nl()
        self.expect(")")
        return node

    def statement(self):
        keyword = self.keyword_at()
        if keyword == "if":
            self.pos += 2
            branches = [(self.condition(), self.block())]
            other = None
            while True:
                save = self.pos
                self.skip_ws_nl()
                kw = self.keyword_at()
                if kw == "elseif":
                    self.pos += 6
                    branches.append((self.condition(), self.block()))
                elif kw == "else":
                    self.pos += 4
                    other = self.block()
                    break
                else:
                    self.pos = save
                    break
            return ("if", branches, other)
        if keyword == "foreach":
            self.pos += 7
            self.skip_ws()
            self.expect("(")
            self.skip_ws()
            var = SIMPLE_VARIABLE.match(self.src, self.pos)
            if not var:
                self.error("Missing variable name after foreach.")
            self.pos = var.end()
            self.skip_ws()
            if not re.compile(r"in\b", re.IGNORECASE).match(self.src, self.pos):
                self.error("Missing 'in' after variable in foreach loop.")
            self.pos += 2
            self.skip_ws()
            collection = self.pipeline()
            self.expect(")")
            return ("foreach", var.group(0)[1:].lower(), collection, self.block())
        if keyword == "for":
            self.pos += 3
            self.skip_ws()
            self.expect("(")
            parts = []
            for closing in (";", ";", ")"):
                self.skip_ws()
                parts.append(None if self.peek() == closing else self.statement())
                self.expect(closing)
            return ("for", parts[0], parts[1], parts[2], self.block())
        if keyword == "while":
            self.pos += 5
            return ("while", self.condition(), self.block())
        if keyword in ("break", "continue"):
            self.pos += len(keyword)
            return (keyword,)
        if keyword in ("return", "exit"):
            self.pos += len(keyword)
            self.skip_ws()
            value = None if self.at_end() or self.peek() in ";\n}" else self.pipeline()
            return ("return", value)
        if keyword == "throw":
            self.pos += 5
            self.skip_ws()
            return ("throw", None if self.at_end() or self.peek() in ";\n}" else self.pipeline())
        if keyword in ("function", "filter", "switch", "try", "do", "trap", "class", "enum", "param"):
            raise Unsupported(f"'{keyword}' is not supported in the simulated terminal.")
        return self.pipeline(allow_assignment=True)

    # pipelines and commands ---------------------------------------------------------
    def pipeline(self, allow_assignment: bool = False):
        saved, self.no_comma = self.no_comma, False
        try:
            return self._pipeline(allow_assignment)
        finally:
            self.no_comma = saved

    def _pipeline(self, allow_assignment: bool = False):
        self.skip_ws()
        first = self.element()
        if allow_assignment:
            self.skip_ws()
            for op in ("+=", "-=", "*=", "/=", "="):
                if self.starts(op) and not self.starts("=="):
                    if first[0] not in ("var", "member", "index"):
                        self.error("The assignment expression is not valid.")
                    self.pos += len(op)
                    self.skip_ws_nl()
                    value = self.pipeline(allow_assignment=True)
                    return ("assign", op, first, value)
        elements = [first]
        redirects = []
        while True:
            self.skip_ws()
            redirect = self.redirection()
            if redirect:
                redirects.append(redirect)
                continue
            if self.peek() == "|" and self.peek(1) != "|":
                self.pos += 1
                self.skip_ws_nl()
                elements.append(self.element())
                continue
            break
        if len(elements) == 1 and not redirects and first[0] != "cmd":
            return first
        return ("pipeline", elements, redirects)

    def redirection(self):
        match = re.compile(r"(2>&1|\*>>|\*>|2>>|2>|>>|>)").match(self.src, self.pos)
        if not match:
            return None
        self.pos = match.end()
        op = match.group(1)
        if op == "2>&1":
            return ("merge",)
        self.skip_ws()
        target = self.argument_value()
        return (op, target)

    def element(self):
        self.skip_ws()
        ch = self.peek()
        if ch == "&":
            self.pos += 1
            self.skip_ws()
            name_node = self.argument_value()
            return ("cmd", name_node, self.arguments())
        if ch == "." and self.peek(1) in " \t":
            raise Unsupported("Dot-sourcing scripts is not supported in the simulated terminal.")
        if self.is_expression_start():
            return self.expression()
        name = self.bare_word()
        if not name:
            self.error(f"Unexpected token '{self.src[self.pos:self.pos + 10]}'.")
        return ("cmd", ("const", name), self.arguments())

    def is_expression_start(self) -> bool:
        ch = self.peek()
        if ch == END:
            return False
        if ch in "$('\"@[{!0123456789":
            return True
        if ch == "-":
            nxt = self.peek(1)
            if nxt.isdigit() or nxt == ".":
                return True
            word = self.word_after_dash()
            return word in ("not", "split", "join", "bnot")
        if ch == "." and self.peek(1).isdigit():
            return True
        return False

    def word_after_dash(self) -> str:
        match = re.compile(r"-([A-Za-z]+)").match(self.src, self.pos)
        return match.group(1).lower() if match else ""

    def bare_word(self) -> str:
        start = self.pos
        while not self.at_end() and self.peek() not in ARG_END and self.peek() not in "(":
            if self.peek() in "'\"":
                break
            self.pos += 1
        return self.src[start:self.pos]

    def arguments(self):
        args = []
        while True:
            self.skip_ws()
            ch = self.peek()
            if ch == END or ch in "|;)}\n" or (ch == ">" or (ch in "2*" and self.peek(1) == ">")):
                break
            if ch == "-" and re.compile(r"-[A-Za-z_?]").match(self.src, self.pos) and not self.starts("--"):
                match = re.compile(r"-([A-Za-z_?][\w-]*)(:?)").match(self.src, self.pos)
                self.pos = match.end()
                name = match.group(1)
                if match.group(2):
                    self.skip_ws()
                    args.append(("param", name, self.argument_list()))
                else:
                    args.append(("param", name, None))
                continue
            if self.starts("--%"):
                raise Unsupported("The stop-parsing token (--%) is not supported in the simulated terminal.")
            args.append(("arg", self.argument_list()))
        return args

    def argument_list(self):
        values = [self.argument_value()]
        while True:
            save = self.pos
            self.skip_ws()
            if self.peek() == ",":
                self.pos += 1
                self.skip_ws_nl()
                values.append(self.argument_value())
            else:
                self.pos = save
                break
        return values[0] if len(values) == 1 else ("array", values)

    def argument_value(self):
        ch = self.peek()
        if ch in "'\"":
            node = self.string_literal()
            return self.postfix(node) if self.peek() == "." and not self.peek(1) in " /\\" else node
        if ch in "(@{" or self.starts("$("):
            return self.postfix(self.primary())
        if ch == "$":
            end = self.pos
            depth = 0
            while end < len(self.src) and (self.src[end] not in ARG_END or depth):
                if self.src[end] in "[(":
                    depth += 1
                elif self.src[end] in "])":
                    depth = max(depth - 1, 0)
                end += 1
            token = self.src[self.pos:end]
            if re.fullmatch(r"\$(?:[A-Za-z_]\w*:)?[\w?^$]+(?:\.[\w#'\"]+(?:\([^)]*\))?|\[[^\]]*\])*", token):
                return self.postfix(self.primary())
            self.pos = end
            return expandable(token)
        start = self.pos
        while not self.at_end() and self.peek() not in ARG_END:
            if self.peek() in "'\"":
                quote = self.peek()
                close = self.src.find(quote, self.pos + 1)
                self.pos = len(self.src) if close == -1 else close + 1
                continue
            self.pos += 1
        text = self.src[start:self.pos]
        number = NUMBER.fullmatch(text)
        if number and not text.startswith("0x") or (number and text.lower().startswith("0x")):
            return ("const", number_value(number.group(1), number.group(2)))
        if text.startswith("-") and NUMBER.fullmatch(text[1:]):
            inner = NUMBER.fullmatch(text[1:])
            return ("const", -number_value(inner.group(1), inner.group(2)))
        if text.lower() in ("$true", "$false", "$null"):
            return ("const", {"$true": True, "$false": False, "$null": None}[text.lower()])
        if "'" in text or '"' in text:
            return ("const", re.sub(r"""['"]""", "", text))
        return ("const", text)

    # expressions -----------------------------------------------------------------
    def expression(self):
        return self.logical()

    def operator_word(self, allowed) -> str:
        save = self.pos
        self.skip_ws()
        match = re.compile(r"-([A-Za-z]+)\b").match(self.src, self.pos)
        if match and match.group(1).lower() in allowed:
            self.pos = match.end()
            self.skip_ws_nl()
            return match.group(1).lower()
        self.pos = save
        return ""

    def logical(self):
        left = self.bitwise()
        while True:
            op = self.operator_word(LOGICAL)
            if not op:
                return left
            left = (op, left, self.bitwise())

    def bitwise(self):
        left = self.comparison()
        while True:
            op = self.operator_word(BITWISE)
            if not op:
                return left
            left = ("binop", op, left, self.comparison())

    def comparison(self):
        left = self.additive()
        while True:
            op = self.operator_word(COMPARISON | CASED)
            if not op:
                return left
            if op in ("is", "isnot", "as"):
                self.skip_ws()
                right = self.type_literal() if self.peek() == "[" else self.additive()
            else:
                right = self.additive()
            left = ("binop", op, left, right)

    def additive(self):
        left = self.multiplicative()
        while True:
            save = self.pos
            self.skip_ws()
            ch = self.peek()
            if ch in "+-" and self.peek(1) not in "=+-" and not (ch == "-" and re.compile(r"-[A-Za-z]").match(self.src, self.pos)):
                self.pos += 1
                self.skip_ws_nl()
                left = ("binop", ch, left, self.multiplicative())
            else:
                self.pos = save
                return left

    def multiplicative(self):
        left = self.format_expr()
        while True:
            save = self.pos
            self.skip_ws()
            ch = self.peek()
            if ch in "*/%" and self.peek(1) != "=":
                self.pos += 1
                self.skip_ws_nl()
                left = ("binop", ch, left, self.format_expr())
            else:
                self.pos = save
                return left

    def format_expr(self):
        left = self.range_expr()
        while self.operator_word({"f"}):
            left = ("binop", "f", left, self.range_expr())
        return left

    def range_expr(self):
        left = self.unary()
        save = self.pos
        self.skip_ws()
        if self.starts("..") and not self.starts("..."):
            self.pos += 2
            self.skip_ws()
            return ("range", left, self.unary())
        self.pos = save
        return left

    def unary(self):
        self.skip_ws()
        if self.peek() == "!":
            self.pos += 1
            return ("unary", "not", self.unary())
        word = self.word_after_dash() if self.peek() == "-" else ""
        if word in ("not", "bnot", "split", "join") and re.compile(r"-[A-Za-z]+\b").match(self.src, self.pos):
            self.pos += len(word) + 1
            self.skip_ws()
            return ("unary", word, self.unary())
        if self.peek() == "-" and self.peek(1) not in "-=":
            self.pos += 1
            return ("unary", "neg", self.unary())
        if self.peek() == "+" and self.peek(1) not in "+=":
            self.pos += 1
            return ("unary", "pos", self.unary())
        if self.starts("++") or self.starts("--"):
            op = self.src[self.pos:self.pos + 2]
            self.pos += 2
            return ("preinc", op, self.unary())
        return self.comma()

    def comma(self):
        first = self.cast()
        if self.no_comma:
            return first
        items = [first]
        while True:
            save = self.pos
            self.skip_ws()
            if self.peek() == ",":
                self.pos += 1
                self.skip_ws_nl()
                items.append(self.cast())
            else:
                self.pos = save
                break
        return first if len(items) == 1 else ("array", items)

    def cast(self):
        self.skip_ws()
        if self.peek() == "[":
            type_node = self.type_literal()
            if self.starts("::"):
                return self.postfix(type_node)
            save = self.pos
            self.skip_ws()
            if self.peek() != END and (self.is_expression_start() or self.peek() in "$(@'\"["):
                return ("cast", type_node[1], self.cast())
            self.pos = save
            return self.postfix(type_node)
        return self.postfix(self.primary())

    def type_literal(self):
        match = re.compile(r"\[\s*([A-Za-z_][\w.]*(?:\[\])?)\s*\]").match(self.src, self.pos)
        if not match:
            self.error("Missing type name after '['.")
        self.pos = match.end()
        return ("type", match.group(1))

    def postfix(self, node):
        while True:
            if self.starts("::"):
                self.pos += 2
                name = self.member_name()
                if self.peek() == "(":
                    node = ("call", node, name, self.call_arguments(), True)
                else:
                    node = ("member", node, name, True)
            elif self.peek() == "." and not self.starts("..") and (self.peek(1).isalpha() or self.peek(1) in "_'\"$("):
                self.pos += 1
                name = self.member_name()
                if self.peek() == "(":
                    node = ("call", node, name, self.call_arguments(), False)
                else:
                    node = ("member", node, name, False)
            elif self.peek() == "[" and node[0] != "type":
                self.pos += 1
                self.skip_ws()
                index = self.expression()
                self.expect("]")
                node = ("index", node, index)
            elif self.starts("++") or self.starts("--"):
                if node[0] not in ("var", "member", "index"):
                    return node
                op = self.src[self.pos:self.pos + 2]
                self.pos += 2
                node = ("postinc", op, node)
            else:
                return node

    def member_name(self):
        ch = self.peek()
        if ch in "'\"":
            return self.string_literal()
        if ch == "$":
            return self.primary()
        if ch == "(":
            return self.primary()
        match = re.compile(r"[A-Za-z_#][\w]*").match(self.src, self.pos)
        if not match:
            self.error("Missing property name after the reference operator.")
        self.pos = match.end()
        return ("const", match.group(0))

    def call_arguments(self):
        self.expect("(")
        args = []
        self.skip_ws_nl()
        if self.peek() == ")":
            self.pos += 1
            return args
        while True:
            self.skip_ws_nl()
            args.append(self.logical_no_comma())
            self.skip_ws_nl()
            if self.peek() == ",":
                self.pos += 1
                continue
            self.expect(")")
            return args

    def logical_no_comma(self):
        saved, self.no_comma = self.no_comma, True
        try:
            return self.logical()
        finally:
            self.no_comma = saved

    def primary(self):
        self.skip_ws()
        ch = self.peek()
        if ch in "'\"":
            return self.string_literal()
        if ch == "$":
            if self.starts("$("):
                self.pos += 2
                body = self.statements(")")
                self.expect(")")
                return ("subexpr", body)
            if self.starts("${"):
                end = self.src.find("}", self.pos)
                if end == -1:
                    self.error("Missing '}' in variable name.")
                name = self.src[self.pos + 2:end]
                self.pos = end + 1
                return ("var", name.lower())
            match = SIMPLE_VARIABLE.match(self.src, self.pos)
            if not match:
                self.pos += 1
                return ("const", "$")
            self.pos = match.end()
            name = match.group(0)[1:].lower()
            if name in ("true", "false", "null"):
                return ("const", {"true": True, "false": False, "null": None}[name])
            return ("var", name)
        if ch == "@":
            if self.starts("@("):
                self.pos += 2
                body = self.statements(")")
                self.expect(")")
                return ("arraysub", body)
            if self.starts("@{"):
                return self.hashtable()
            if self.starts("@'") or self.starts('@"'):
                raise Unsupported("Here-strings are not supported in the simulated terminal.")
            self.error("Unrecognized token '@'.")
        if ch == "(":
            self.pos += 1
            self.skip_ws_nl()
            if self.peek() == ")":
                self.pos += 1
                return ("const", None)
            node = self.pipeline(allow_assignment=True)
            self.skip_ws_nl()
            self.expect(")")
            return ("paren", node)
        if ch == "{":
            self.pos += 1
            start = self.pos
            body = self.statements("}")
            text = self.src[start:self.pos]
            self.expect("}")
            return ("scriptblock", body, text)
        if ch == "[":
            return self.type_literal()
        match = NUMBER.match(self.src, self.pos)
        if match and (ch.isdigit() or ch == "."):
            self.pos = match.end()
            return ("const", number_value(match.group(1), match.group(2)))
        if ch == "-" and (self.peek(1).isdigit()):
            self.pos += 1
            inner = self.primary()
            return ("unary", "neg", inner)
        word = self.word_at()
        if word:
            self.error(f"Unexpected token '{word}' in expression or statement. "
                       f"(Commands go at the start of a pipeline; put them in parentheses inside an expression.)")
        self.error(f"Unexpected token '{ch if ch != END else 'end of line'}' in expression or statement.")

    def hashtable(self):
        self.pos += 2  # @{
        entries = []
        while True:
            self.skip_ws_nl()
            while self.peek() == ";":
                self.pos += 1
                self.skip_ws_nl()
            if self.peek() == "}":
                self.pos += 1
                return ("hash", entries)
            if self.peek() in "'\"":
                key = self.string_literal()
            elif self.peek() == "(":
                key = self.primary()
            else:
                match = re.compile(r"[\w.-]+").match(self.src, self.pos)
                if not match:
                    self.error("Missing key before '=' in hash literal.")
                self.pos = match.end()
                number = NUMBER.fullmatch(match.group(0))
                key = ("const", number_value(number.group(1), number.group(2)) if number else match.group(0))
            self.skip_ws()
            self.expect("=")
            self.skip_ws_nl()
            value = self.pipeline(allow_assignment=False)
            entries.append((key, value))
            self.skip_ws()
            if self.peek() not in (";", "\n", "}"):
                self.error("Missing statement after '=' in hash literal, or a missing ';' between entries.")

    def string_literal(self):
        quote = self.peek()
        self.pos += 1
        buf = []
        if quote == "'":
            while True:
                if self.at_end():
                    self.error("The string is missing the terminator: '.")
                ch = self.peek()
                if ch == "'":
                    if self.peek(1) == "'":
                        buf.append("'")
                        self.pos += 2
                        continue
                    self.pos += 1
                    return ("const", "".join(buf))
                buf.append(ch)
                self.pos += 1
        start = self.pos
        while True:
            if self.at_end():
                self.error('The string is missing the terminator: ".')
            ch = self.peek()
            if ch == "`":
                self.pos += 2
                continue
            if ch == '"':
                if self.peek(1) == '"':
                    self.pos += 2
                    continue
                break
            if self.starts("$("):
                depth = 0
                while not self.at_end():
                    if self.peek() == "(":
                        depth += 1
                    elif self.peek() == ")":
                        depth -= 1
                        if depth == 0:
                            break
                    self.pos += 1
            self.pos += 1
        text = self.src[start:self.pos]
        self.pos += 1
        return expandable(text, in_quotes=True)


ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "0": "\0", "a": "\a", "b": "\b", "e": "\x1b", "f": "\f", "v": "\v"}


def expandable(text: str, in_quotes: bool = False):
    """A double-quoted string (or an argument such as $HOME/logs): text with $var, ${var} and $(...)."""
    parts: list = []
    buf: list[str] = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "`" and i + 1 < len(text):
            buf.append(ESCAPES.get(text[i + 1], text[i + 1]))
            i += 2
            continue
        if ch == '"' and in_quotes and text.startswith('""', i):
            buf.append('"')
            i += 2
            continue
        if ch == "$":
            if text.startswith("$(", i):
                depth = 0
                j = i + 1
                while j < len(text):
                    if text[j] == "(":
                        depth += 1
                    elif text[j] == ")":
                        depth -= 1
                        if depth == 0:
                            break
                    j += 1
                inner = Parser(text[i + 2:j])
                node = ("subexpr", inner.parse())
                if buf:
                    parts.append("".join(buf))
                    buf = []
                parts.append(node)
                i = j + 1
                continue
            if text.startswith("${", i):
                end = text.find("}", i)
                if end != -1:
                    if buf:
                        parts.append("".join(buf))
                        buf = []
                    parts.append(("var", text[i + 2:end].lower()))
                    i = end + 1
                    continue
            match = SIMPLE_VARIABLE.match(text, i)
            if match:
                if buf:
                    parts.append("".join(buf))
                    buf = []
                name = match.group(0)[1:].lower()
                parts.append(("const", {"true": True, "false": False, "null": None}[name])
                             if name in ("true", "false", "null") else ("var", name))
                i = match.end()
                continue
        buf.append(ch)
        i += 1
    if buf:
        parts.append("".join(buf))
    if all(isinstance(p, str) for p in parts):
        return ("const", "".join(parts))
    return ("xstr", parts)


def parse(source: str):
    return Parser(source).parse()
