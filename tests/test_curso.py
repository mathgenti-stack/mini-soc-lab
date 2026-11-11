"""The course page (estudar.html) and its sources in curso/: new topics, quiz, path and look."""
import importlib.util
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAGE = (ROOT / "estudar.html").read_text(encoding="utf-8")


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "curso" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    import sys
    sys.path.insert(0, str(ROOT / "curso"))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(ROOT / "curso"))
    return module


def test_building_again_changes_nothing():
    """estudar.html is up to date with curso/ (run `python curso/montar.py` after editing the sources)."""
    montar = load("montar")
    assert montar.build(PAGE) == PAGE


def test_every_topic_is_on_the_path_once():
    topics = load("topicos_novos")
    top = PAGE[PAGE.index("\nconst TOP=[\n"):]
    top = top[:top.index("\n];")]
    ids = re.findall(r'^\{id:"([\w-]+)",', top, re.M)
    on_path = [i for m in topics.TRILHA for i in m["ids"]]
    assert sorted(on_path) == sorted(set(on_path)), "a topic appears twice on the path"
    assert set(on_path) == set(ids), set(ids) ^ set(on_path)


def test_new_topics_follow_the_course_template():
    topics = load("topicos_novos")
    quiz = load("quiz_novo")
    for t in topics.NEW_TOPICS:
        assert "No dia a dia de um SOC" in t["st"] or "No dia a dia de um Service Desk" in t["st"], t["id"]
        for section in ("Erros comuns", "Como explicar numa entrevista"):
            assert section in t["st"], (t["id"], section)
        assert 6 <= len(t["chk"]) <= 9, t["id"]
        assert sum(q[0] in t["tags"] for q in quiz.Q) >= 10, t["id"]
        assert t["id"] in topics.RESUMOS


def test_every_topic_has_the_soc_and_interview_sections():
    for tid, body in re.findall(r'^\{id:"([\w-]+)",.*?st:(`.*?`|".*?(?<!\\)")\}', PAGE, re.M | re.S):
        assert "Como explicar numa entrevista" in body, tid


def test_no_study_diary_left():
    """The page is a course for other people, not the author's notes on the rooms they were taking."""
    for text in ("Em breve", "Próxima sala", "A página segue as tarefas da sala", "Task 1 ·", "Na sala, você",
                 "Exemplo da sala", "candidatura ou um ajuste no CV", "trilha Pre Security da TryHackMe"):
        assert text not in PAGE, text


def test_learner_path_pieces_are_wired():
    for code in ("function trilha()", "function nextStep(t)", "function openTopic(t,tab)", 'class="steps"',
                 "function welcome()", 'id="hcont"', 'id="qback"'):
        assert code in PAGE, code


def test_ticket_queue_is_wired():
    """The Service Desk ticket queue (menu Chamados): view, menu button, tickets and the practice step of topics."""
    chamados = load("chamados")
    for code in ('<button data-t="9">', '<div id="v9" class="hide">', "if(n==9)rSd();", "function rSd()",
                 "function tkStart(t)", "lc=pratCount(t)", "FILA[t.id]?sdPrat(t)", '{id:"sd",ic:"🎧"'):
        assert code in PAGE, code
    assert len(chamados.TICKETS) >= 12
    assert {1, 2, 3} == {t["nivel"] for t in chamados.TICKETS}
    # every Service Desk topic has tickets to practise
    for topic in ("sd", "atend", "trouble", "contas"):
        assert any(topic in t["topicos"] for t in chamados.TICKETS), topic


def test_path_has_two_phases():
    topics = load("topicos_novos")
    phases = [m for m in topics.TRILHA if m.get("f")]
    assert [m["f"].split(" ·")[0] for m in phases] == ["Fase 1", "Fase 2"]
    assert topics.TRILHA[0] is phases[0]
    first = [i for m in topics.TRILHA[:topics.TRILHA.index(phases[1])] for i in m["ids"]]
    assert {"sd", "atend", "trouble", "contas"} <= set(first) and "soc" not in first

