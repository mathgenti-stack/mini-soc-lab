"""Grava os tópicos novos, as perguntas de quiz, a trilha e a Fila de chamados do curso em estudar.html.

Uso (na pasta do projeto):  python curso/montar.py
Pode rodar quantas vezes quiser: o que foi gravado antes, entre as marcas /* >>> curso */ e /* <<< curso */,
é substituído. O resto da página não muda.
"""
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from chamados import CATEGORIAS, TICKETS, TIPOS  # noqa: E402
from quiz_novo import Q  # noqa: E402
from topicos_novos import NEW_TOPICS, RESUMOS, TRILHA  # noqa: E402

PAGE = Path(__file__).resolve().parents[1] / "estudar.html"
BEGIN, END = "/* >>> curso */", "/* <<< curso */"


def js(value):
    return json.dumps(value, ensure_ascii=False)


def array_bounds(html, name):
    start = html.index(f"\nconst {name}=[\n") + 1
    end = html.index("\n];", start)
    return start, end


def put_in_array(html, name, entries):
    """Append entries (JS source lines) at the end of `const name=[...]`, replacing an earlier run."""
    start, end = array_bounds(html, name)
    body = html[start:end]
    if BEGIN in body:
        body = body[:body.index(BEGIN)].rstrip().rstrip(",")
    block = ",\n" + BEGIN + "\n" + ",\n".join(entries) + "\n" + END
    return html[:start] + body.rstrip() + block + html[end:]


def check(topics, questions, trilha):
    ids = [t["id"] for t in topics]
    assert len(ids) == len(set(ids)), "id repetido"
    tags = {tag for t in topics for tag in t["tags"]}
    for q in questions:
        assert q[0] in tags, f"etiqueta sem tópico: {q[0]}"
        assert len(q[2]) == 4 and len(q[4]) == 3 and len(set(q[2])) == 4, q[1]
    for t in topics:
        n = sum(1 for q in questions if q[0] in t["tags"])
        goal = [c for c in t["chk"] if c.startswith("Acertar ")]
        assert goal and re.match(r"Acertar \d+ de \d+ no quiz", goal[0]), t["id"]
        assert n >= 10, f"{t['id']}: só {n} perguntas"
    for m in trilha:
        assert m["n"] and m["ids"], m


def check_tickets(tickets, topic_ids):
    """Os chamados da Fila: campos completos, alternativas válidas e a nota modelo passando na própria correção."""
    ids = [t["id"] for t in tickets]
    assert len(ids) == len(set(ids)), "chamado repetido"
    for t in tickets:
        tid = t["id"]
        assert t["nivel"] in (1, 2, 3) and t["titulo"] and t["msg"] and t["quem"], tid
        assert set(t["topicos"]) <= topic_ids, (tid, set(t["topicos"]) - topic_ids)
        tri = t["triagem"]
        assert tri["tipo"] in TIPOS and set([tri["cat"]] if isinstance(tri["cat"], str) else tri["cat"]) <= set(CATEGORIAS), tid
        assert tri["impacto"] in (1, 2, 3) and tri["urgencia"] in (1, 2, 3) and tri["porque"], tid
        ok = [q for q in t["perguntas"] if q["ok"]]
        assert len(t["perguntas"]) == 6 and len(ok) >= 3 and all(q["p"] and q["r"] and q["porque"] for q in t["perguntas"]), tid
        cmds = t["terminal"]["cmds"]
        assert cmds and all(c["c"] and c["out"] for c in cmds) and t["terminal"]["onde"] and t["terminal"]["dica"], tid
        for k in ("diag", "acao"):
            assert len(t[k]["ops"]) == 4 and len(set(t[k]["ops"])) == 4 and t[k]["porque"], (tid, k)
        model = t["nota"]["modelo"].lower()
        for name, rx in t["nota"]["itens"]:
            assert re.search(rx, model), (tid, "a nota modelo não passa no item", name)


def build(html):
    check(NEW_TOPICS, Q, TRILHA)
    existing = set(re.findall(r'^\{id:"([\w-]+)"', html[slice(*array_bounds(html, "TOP"))], re.M))
    new_ids = {t["id"] for t in NEW_TOPICS}
    clash = existing & new_ids
    start, end = array_bounds(html, "TOP")
    if BEGIN not in html[start:end]:
        assert not clash, f"já existem na página: {clash}"
    html = put_in_array(html, "TOP", [
        "{" + ",".join(f"{k}:{js(t[k])}" for k in ("id", "n", "ic", "tags", "st", "chk")) + "}" for t in NEW_TOPICS])
    html = put_in_array(html, "MQ", [js([q[0], q[1], q[2], q[3]]) for q in Q])
    html = put_in_array(html, "WR", [js(q[4]) for q in Q])
    html = put_in_array(html, "DET", [js(q[5]) for q in Q])
    html = put_in_array(html, "EX", [js(q[6]) for q in Q])
    # the course path (replaces the old TryHackMe modules)
    all_ids = existing | new_ids
    for m in TRILHA:
        missing = set(m["ids"]) - all_ids
        assert not missing, f"trilha cita tópicos que não existem: {missing}"
    # the look (curso/visual.css), at the end of the page's <style>
    css = (Path(__file__).resolve().parent / "visual.css").read_text(encoding="utf-8").strip()
    cmark = BEGIN + "\n/* ===== Visual do curso"
    if cmark in html:
        a = html.index(cmark)
        html = html[:a] + html[html.index(END, a) + len(END) + 1:]
    assert html.count("</style></head>") == 1
    html = html.replace("</style></head>", BEGIN + "\n" + css + "\n" + END + "\n</style></head>")
    # the 1-minute summaries (Recapitular): one statement right before `function dkey`
    assert set(RESUMOS) == new_ids, "cada tópico novo precisa de um resumo"
    mark = BEGIN + "\nObject.assign(RC,"
    if mark in html:
        a = html.index(mark)
        html = html[:a] + html[html.index(END, a) + len(END) + 1:]
    rc = mark + js(RESUMOS) + ");\n" + END + "\n"
    html = html.replace("\nfunction dkey(", "\n" + rc + "function dkey(", 1)
    # the ticket queue (Fila de chamados): the tickets as JSON and the engine (curso/chamados.js),
    # right before the page starts up
    check_tickets(TICKETS, all_ids)
    engine = (Path(__file__).resolve().parent / "chamados.js").read_text(encoding="utf-8").strip()
    fmark = BEGIN + "\nconst TK_TIPOS="
    if fmark in html:
        a = html.index(fmark)
        html = html[:a] + html[html.index(END, a) + len(END) + 1:]
    init = '\nrC();rT();$("s2")'
    assert html.count(init) == 1
    block = (fmark + js(TIPOS) + ";\nconst TK_CATS=" + js(CATEGORIAS) + ";\nconst TK=" + js(TICKETS) + ";\n"
             + engine + "\n" + END)
    html = html.replace(init, "\n" + block + init, 1)
    start = html.index("\nconst MODS=[\n") + 1
    end = html.index("\n];", start) + 3
    mods = "const MODS=[\n" + ",\n".join(js(m) for m in TRILHA) + "\n];"
    html = html[:start] + mods + html[end:]
    return html


if __name__ == "__main__":
    html = PAGE.read_text(encoding="utf-8")
    new = build(html)
    PAGE.write_text(new, encoding="utf-8", newline="\n")
    print(f"ok: {len(NEW_TOPICS)} tópicos, {len(Q)} perguntas, {len(TRILHA)} módulos na trilha, {len(TICKETS)} chamados")
