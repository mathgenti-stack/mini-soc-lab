"""Training score: an automatic checklist of the key points each answer should contain.

Each check is built from the alert's own data (accounts, addresses, counts, success, timing,
technique) and, when the ground truth is known, from the expected verdict and status. An answer
passes a check when it mentions the point, in English or Portuguese.

This is keyword matching, not a judgement of the reasoning: a correct answer worded differently
can miss a check, and a check can pass on a sentence that says the opposite ("not an attack"
contains "attack"). The score is a study aid that shows which facts were left out.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

from . import training
from .detection.context import DetectionContext
from .i18n import Msg
from .models import Alert, EventType, Result
from .reporting import InvestigationReport

MAX_LISTED = 3  # for long lists (a spray against 16 accounts), naming this many is enough

# Patterns run on lower-case text without accents ("não" -> "nao"), so each covers EN and PT-BR.
WORDS = {
    "attack": r"attack|ataque|malicio|compromi|intrus|invas|true positive|verdadeiro positivo|brute.?force|"
              r"forca bruta|spray|credential stuffing|unauthori[sz]ed|nao autorizad",
    "benign": r"benign|legitim|false positive|falso positivo|normal|esquec|forgot|authori[sz]ed|autorizad|"
              r"expected|esperad|inofensiv|harmless|configura|expired|expirad",
    "uncertain": r"uncertain|incert|ambigu|inconclus|not sure|nao (sei|tenho certeza)|unclear|verif|confirm|"
                 r"investigat|investigar|depende|depends",
    "escalate": r"escalat|escal[ao]|escalonar|tier ?2|nivel ?2|\bn2\b|\bl2\b|incident response|resposta a incidente",
    "close": r"\bclos|fech|encerr|arquiv",
    "verify": r"verif|confirm|contat|contact|ligar|perguntar|\bask|check with|consult",
    "contain": r"reset|redefin|trocar a senha|change (the|their|his|her)? ?password|block|bloque|disable|desativ|"
               r"desabilit|revok|revog|\bmfa\b|isolat|isolar|sess",
    "lockout": r"lock|bloque|trav",
    "unlock": r"unlock|desbloque|destrav|reativ",
    "password_change": r"password.?change|changed .{0,15}password|password (was |were |had been )?(changed|reset)|"
                       r"senha (foi )?(trocada|alterada|mudada)|troc\w* (de |a )?senha|mud\w* (a )?senha|"
                       r"alter\w* (a )?senha|nova senha|new password|redefini",
    "service": r"servi[c]|service|svc_|automat|backup|sistema|system|aplica",
    "person": r"user|usuari|pessoa|person|human|funcionari|employee|staff|colaborador|conta de usuario",
    "external": r"extern|internet|publico|public|fora da (rede|empresa)|outside the (company|network)",
    "internal": r"intern|\b10\.|rede (da empresa|corporativa)|company network|corporate|local",
    "outside_hours": r"outside|fora|night|noite|evening|weekend|fim de semana|madrugada|after.?hours|off.?hours|"
                     r"out of hours|sabado|domingo|saturday|sunday",
    "inside_hours": r"business hours|working hours|office hours|horario comercial|expediente|horario de trabalho|"
                    r"dentro do horario|durante o dia|during the day|within (business|working) hours",
    "no": r"\bno\b|\bnot\b|\bnone\b|\bnao\b|nenhu|\bsem\b|didn.?t|did not|never|nunca|wasn.?t|was not",
    "success": r"succe|sucesso|logged (in|on)|logou|entrou|conseguiu|acess|accepted|bem.?sucedid|login (ok|valido)",
    "contacts": r"user|usuari|service ?desk|help ?desk|suporte|ticket|chamado|manager|gestor|gerente|team|equipe|"
                r"owner|dono|responsavel|infra|rh\b|\bhr\b|tier ?2|nivel ?2",
    "benign_ideas": r"forg|esquec|typo|digit|errou|scanner|scan|varredura|on.?call|plantao|travel|viag|vpn|servi[c]|"
                    r"service|expired|expirad|misconfig|configura|nova senha|new password|celular|mobile|hotel|caps",
    "severity": r"\blow\b|medium|high|critical|baix|medi|\balt|critic",
}


@dataclass(frozen=True)
class Check:
    question_id: str
    label: Msg
    passed: bool


@dataclass(frozen=True)
class ScoreCard:
    checks: tuple[Check, ...]

    @property
    def earned(self) -> int:
        return sum(check.passed for check in self.checks)

    @property
    def total(self) -> int:
        return len(self.checks)

    @property
    def percent(self) -> int:
        return round(100 * self.earned / self.total) if self.total else 0

    def for_question(self, question_id: str) -> list[Check]:
        return [check for check in self.checks if check.question_id == question_id]


def normalise(text: str) -> str:
    decomposed = unicodedata.normalize("NFKD", text.lower())
    return "".join(char for char in decomposed if not unicodedata.combining(char))


def _has(text: str, word: str) -> bool:
    return re.search(WORDS[word], text) is not None


def _mentions(text: str, value: str) -> bool:
    return normalise(value) in text


def _mentions_number(text: str, number: int) -> bool:
    return re.search(rf"(?<![\d.]){number}(?![\d])", text) is not None


def _mentions_enough(text: str, values: list[str]) -> bool:
    found = sum(_mentions(text, value) for value in values)
    return found >= min(len(values), MAX_LISTED)


def expected_verdict(scenario: str | None, report: InvestigationReport) -> str:
    """'attack', 'benign' or 'uncertain': from the ground truth, else from the tool's conclusion."""
    if scenario:
        if scenario.startswith("simulated_"):
            return "attack"
        if scenario.startswith("ambiguous_"):
            return "uncertain"
        return "benign"
    conclusion = report.conclusion
    first = conclusion.params["parts"][0] if getattr(conclusion, "key", "") is None else conclusion  # Msg.join
    return {"conclusion.external_success": "attack", "conclusion.benign": "benign"}.get(
        getattr(first, "key", None), "uncertain")


def score_answers(answers: dict[str, str], alert: Alert, report: InvestigationReport, config: dict,
                  scenario: str | None = None, status: str | None = None) -> ScoreCard:
    ctx = DetectionContext.from_config(config)
    evidence = report.evidence
    text = {qid: normalise(answers.get(qid, "")) for qid in training.QUESTION_IDS}
    checks: list[Check] = []

    def check(question_id: str, key: str, passed: bool, **params) -> None:
        checks.append(Check(question_id, Msg(f"score.check.{key}", **params), bool(text[question_id]) and passed))

    # Understand
    check("rule", "rule_id", _mentions(text["rule"], alert.rule_id), rule=alert.rule_id)
    if alert.usernames:
        check("scope", "accounts", _mentions_enough(text["scope"], alert.usernames),
              values=", ".join(alert.usernames[:MAX_LISTED]) + (" ..." if len(alert.usernames) > MAX_LISTED else ""))
    if alert.source_ips:
        check("scope", "ips", _mentions_enough(text["scope"], alert.source_ips),
              values=", ".join(alert.source_ips[:MAX_LISTED]) + (" ..." if len(alert.source_ips) > MAX_LISTED else ""))

    # Facts
    failures = evidence[(evidence["event_type"] == EventType.LOGON) & (evidence["result"] == Result.FAILURE)]
    if not failures.empty:
        check("counts", "failure_count", _mentions_number(text["counts"], len(failures)), count=len(failures))
        accounts = failures["username"].nunique()
        if accounts > 1:
            check("counts", "account_count", _mentions_number(text["counts"], accounts), count=accounts)
    success_keys = {getattr(f, "key", None) for f in report.context_findings}
    if "finding.success" in success_keys:
        winners = sorted(set(evidence.loc[(evidence["event_type"] == EventType.LOGON)
                                          & (evidence["result"] == Result.SUCCESS), "username"]))
        check("success", "success_yes", _has(text["success"], "success")
              and (not winners or any(_mentions(text["success"], w) for w in winners)),
              users=", ".join(winners) or "-")
    else:
        check("success", "success_no", _has(text["success"], "no"))
    external = any(not ctx.is_internal(ip) for ip in alert.source_ips)
    check("source", "external" if external else "internal", _has(text["source"], "external" if external else "internal"))
    inside = ctx.is_business_hours(alert.first_seen)
    check("time", "inside_hours" if inside else "outside_hours",
          _has(text["time"], "inside_hours" if inside else "outside_hours"))
    present = set(evidence["event_type"])
    account_events = [(EventType.ACCOUNT_LOCKOUT, "lockout"), (EventType.ACCOUNT_UNLOCK, "unlock"),
                      (EventType.PASSWORD_CHANGE, "password_change")]
    if present & {kind for kind, _ in account_events} or "finding.password_change" in success_keys:
        for kind, word in account_events:
            if kind in present or (word == "password_change" and "finding.password_change" in success_keys):
                check("account_events", word, _has(text["account_events"], word))
    else:
        check("account_events", "no_account_events", _has(text["account_events"], "no"))

    # Context
    if any(ctx.is_service_account(user) for user in alert.usernames):
        check("account_type", "service", _has(text["account_type"], "service"))
    elif alert.usernames:
        check("account_type", "person", _has(text["account_type"], "person"))
    check("benign", "benign_idea", _has(text["benign"], "benign_ideas"))
    check("missing", "contact", _has(text["missing"], "contacts"))

    # Decide
    verdict = expected_verdict(scenario, report)
    check("verdict", f"verdict_{verdict}", _has(text["verdict"], verdict))
    check("severity", "severity_level", _has(text["severity"], "severity"))
    techniques = re.findall(r"T\d{4}(?:\.\d{3})?", alert.mitre_attack or "")
    if techniques:
        check("mitre", "technique", any(re.search(rf"\b{re.escape(t.lower())}\b", text["mitre"]) for t in techniques),
              techniques=" / ".join(techniques))
    guide = training.SCENARIO_GUIDES.get(scenario) if scenario else None
    expected_action = ("escalate" if guide and "Escalated" in guide.expected_statuses and verdict != "uncertain"
                       else "close" if guide and all(s.startswith("Closed") for s in guide.expected_statuses)
                       else {"attack": "escalate", "benign": "close"}.get(verdict, "verify"))
    check("action", f"action_{expected_action}", _has(text["action"], expected_action))
    if verdict == "attack":
        check("action", "containment", _has(text["action"], "contain"))
    if guide and status is not None:
        expected = Msg.join([Msg(f"status.{s}") for s in guide.expected_statuses], " / ")
        checks.append(Check("verdict", Msg("score.check.status", expected=expected), status in guide.expected_statuses))

    # Communicate
    sentences = [s for s in re.split(r"[.!?]+(?:\s|$)", answers.get("summary", "")) if len(s.split()) >= 3]
    check("summary", "summary_length", len(sentences) >= 3)
    check("summary", "summary_entity", _mentions(text["summary"], alert.entity), entity=alert.entity)
    return ScoreCard(tuple(checks))
