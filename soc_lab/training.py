"""Training mode: a structured triage questionnaire for practising Tier 1 SOC analysis.

The analyst answers a fixed set of questions about an alert *before* seeing the tool's own
analysis, then compares each answer with a reference built from the alert, the investigation
report and (when available) the ground-truth scenario labels.

Questions are written in Portuguese and English. Reference answers that come straight from the
report (facts, playbooks, conclusion) stay in English, as the rest of the tool does.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import pandas as pd

from .detection.context import DetectionContext
from .models import Alert, EventType, Result, format_timestamp
from .reporting import InvestigationReport

LANGUAGES = ("pt", "en")
WEEKDAYS_PT = ["segunda", "terça", "quarta", "quinta", "sexta", "sábado", "domingo"]
NOT_ATTACK_SCENARIOS = {"normal", "data_quality_test"}


# ---------------------------------------------------------------------------
# Questions
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Stage:
    id: str
    pt: str
    en: str


@dataclass(frozen=True)
class Question:
    id: str
    stage: str
    pt: str
    en: str
    hint_pt: str
    hint_en: str

    def text(self, lang: str) -> str:
        return self.pt if lang == "pt" else self.en

    def hint(self, lang: str, **values) -> str:
        text = self.hint_pt if lang == "pt" else self.hint_en
        return text.format(**values) if values else text


STAGES = [
    Stage("understand", "1. Entender o alerta", "1. Understand the alert"),
    Stage("facts", "2. Coletar os fatos", "2. Collect the facts"),
    Stage("context", "3. Dar contexto", "3. Add context"),
    Stage("decide", "4. Decidir", "4. Decide"),
    Stage("communicate", "5. Comunicar", "5. Communicate"),
]

QUESTIONS = [
    Question(
        "rule", "understand",
        "Qual regra disparou e que comportamento ela tenta detectar? Explique com as suas palavras.",
        "Which rule fired, and what behaviour is it trying to detect? Explain in your own words.",
        "Olhe 'Detection rule' no topo. Pense: que tipo de ataque essa regra quer pegar?",
        "Look at 'Detection rule' at the top. Think: what kind of attack does this rule want to catch?"),
    Question(
        "scope", "understand",
        "Quem e o que está envolvido? Liste as contas, os IPs de origem, as máquinas e o período (início e fim).",
        "Who and what is involved? List the accounts, source IPs, hosts and the time window (start and end).",
        "Está no resumo do alerta, logo abaixo dos números.",
        "It is in the alert summary, just below the numbers."),
    Question(
        "counts", "facts",
        "Quantas falhas de login aconteceram, contra quantas contas diferentes, e em quanto tempo?",
        "How many failed logons happened, against how many different accounts, and over how long?",
        "Conte as linhas com result = FAILURE na tabela de evidências. Compare o primeiro e o último horário.",
        "Count the rows with result = FAILURE in the evidence table. Compare the first and last timestamps."),
    Question(
        "success", "facts",
        "Houve algum login com SUCESSO durante ou logo depois das falhas? De qual conta e de qual IP?",
        "Was there any SUCCESSFUL logon during or shortly after the failures? Which account, from which IP?",
        "Na aba Event Explorer, pesquise pelo IP de origem e pela conta. Procure result = SUCCESS. "
        "Esta é a pergunta mais importante: sucesso pode significar que o atacante entrou.",
        "In the Event Explorer tab, search for the source IP and the account. Look for result = SUCCESS. "
        "This is the most important question: a success may mean the attacker got in."),
    Question(
        "source", "facts",
        "O IP de origem é interno (rede da empresa, 10.x.x.x) ou externo (internet)? "
        "Esse IP já tinha sido usado antes por essa conta ou por outras?",
        "Is the source IP internal (company network, 10.x.x.x) or external (internet)? "
        "Had this IP been used before by this account or by others?",
        "IPs 10.x.x.x são internos. No Event Explorer, pesquise o IP e veja se ele aparece em dias anteriores.",
        "10.x.x.x addresses are internal. In the Event Explorer, search the IP and check whether it appears on "
        "earlier days."),
    Question(
        "time", "facts",
        "Em que horário e dia isso aconteceu? Foi dentro do horário comercial ou fora (madrugada, noite, fim de semana)?",
        "When did it happen? Was it within business hours or outside them (night, evening, weekend)?",
        "O horário comercial do laboratório é de segunda a sexta, {start:02d}:00 às {end:02d}:00 (UTC).",
        "The lab's business hours are Monday to Friday, {start:02d}:00 to {end:02d}:00 (UTC)."),
    Question(
        "account_events", "facts",
        "A conta foi bloqueada (ACCOUNT_LOCKOUT)? Foi desbloqueada depois (ACCOUNT_UNLOCK)? "
        "Houve troca de senha recente (PASSWORD_CHANGE)?",
        "Was the account locked out (ACCOUNT_LOCKOUT)? Was it unlocked afterwards (ACCOUNT_UNLOCK)? "
        "Was there a recent password change (PASSWORD_CHANGE)?",
        "No Event Explorer, pesquise o nome da conta e olhe a coluna event_type.",
        "In the Event Explorer, search for the account name and look at the event_type column."),
    Question(
        "account_type", "context",
        "Que tipo de conta é: uma pessoa, uma conta de serviço (começa com svc_) ou uma ferramenta/scanner? "
        "Isso muda o risco?",
        "What kind of account is it: a person, a service account (starts with svc_) or a tool/scanner? "
        "Does that change the risk?",
        "Contas de serviço são usadas por sistemas (ex.: backup), não por pessoas. Erros repetidos nelas "
        "costumam ser senha expirada ou configuração errada.",
        "Service accounts are used by systems (e.g. backups), not people. Repeated errors on them are often "
        "an expired password or a misconfiguration."),
    Question(
        "benign", "context",
        "Que explicações inocentes são possíveis? O que faria esse alerta ser um alarme falso?",
        "What innocent explanations are possible? What would make this alert a false alarm?",
        "Pense em: senha esquecida, scanner autorizado, funcionário de plantão, viagem, VPN, conta de serviço.",
        "Think about: forgotten password, authorised scanner, on-call staff, travel, VPN, service account."),
    Question(
        "missing", "context",
        "Que informação está faltando para ter certeza? Com quem você confirmaria (usuário, service desk, "
        "ticket, equipe de infraestrutura, gestor)?",
        "What information is missing to be sure? Who would you confirm with (the user, service desk, a ticket, "
        "the infrastructure team, a manager)?",
        "Um analista nível 1 não adivinha: ele verifica com quem sabe.",
        "A Tier 1 analyst does not guess: they check with someone who knows."),
    Question(
        "verdict", "decide",
        "Qual é o seu veredito: ataque provável, atividade legítima (benigna) ou incerto? Justifique com os fatos.",
        "What is your verdict: likely attack, legitimate (benign) activity, or uncertain? Justify it with the facts.",
        "Use os fatos das etapas 2 e 3. Separe o que você VIU do que você ACHA.",
        "Use the facts from stages 2 and 3. Separate what you SAW from what you THINK."),
    Question(
        "severity", "decide",
        "Você concorda com a severidade que a ferramenta deu? Qual seria a sua e por quê?",
        "Do you agree with the severity the tool assigned? What would yours be, and why?",
        "Pergunte-se: teve sucesso? veio de fora? quantas contas foram atingidas?",
        "Ask yourself: was there a success? did it come from outside? how many accounts were affected?"),
    Question(
        "mitre", "decide",
        "Com qual técnica do MITRE ATT&CK isso parece? (ex.: T1110.001 Password Guessing, "
        "T1110.003 Password Spraying, T1078 Valid Accounts)",
        "Which MITRE ATT&CK technique does this look like? (e.g. T1110.001 Password Guessing, "
        "T1110.003 Password Spraying, T1078 Valid Accounts)",
        "Brute force = muitas senhas em UMA conta. Password spray = poucas senhas em MUITAS contas. "
        "Valid Accounts = o atacante entrou com uma senha válida.",
        "Brute force = many passwords against ONE account. Password spray = few passwords against MANY accounts. "
        "Valid Accounts = the attacker logged in with a valid password."),
    Question(
        "action", "decide",
        "O que você faz agora: fechar, escalar para o nível 2, ou verificar com alguém? "
        "Que ação de contenção você proporia (resetar senha, bloquear IP, desativar conta, revogar sessões)?",
        "What do you do now: close, escalate to Tier 2, or verify with someone? What containment would you "
        "propose (reset password, block IP, disable account, revoke sessions)?",
        "Nível 1 propõe a contenção; quem executa normalmente é outra equipe, seguindo o processo.",
        "Tier 1 proposes containment; another team usually carries it out, following the process."),
    Question(
        "summary", "communicate",
        "Escreva o resumo para o ticket ou para o nível 2 em 3 a 4 frases: o que aconteceu, o que você "
        "verificou e o que recomenda.",
        "Write the summary for the ticket or for Tier 2 in 3 to 4 sentences: what happened, what you checked, "
        "and what you recommend.",
        "Escreva como se a pessoa não tivesse visto nada. Use só fatos e deixe claro o que é hipótese.",
        "Write as if the reader has seen nothing. Use facts only and make clear what is a hypothesis."),
]
QUESTION_IDS = [q.id for q in QUESTIONS]


def questions_for_stage(stage_id: str) -> list[Question]:
    return [q for q in QUESTIONS if q.stage == stage_id]


# ---------------------------------------------------------------------------
# Ground truth ("gabarito")
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ScenarioGuide:
    verdict_pt: str
    verdict_en: str
    explanation_pt: str
    explanation_en: str
    expected_statuses: tuple[str, ...]


SCENARIO_GUIDES = {
    "simulated_brute_force": ScenarioGuide(
        "Ataque real (brute force) sem sucesso",
        "Real attack (brute force), unsuccessful",
        "Um IP externo tentou muitas senhas numa única conta até ela ser bloqueada. Não houve login com sucesso, "
        "então não há sinal de comprometimento. É um verdadeiro positivo: o alerta pegou um ataque de verdade.",
        "An external IP tried many passwords against one account until it was locked out. No logon succeeded, so "
        "there is no sign of compromise. It is a true positive: the alert caught a real attack.",
        ("Closed - True Positive", "Escalated")),
    "simulated_password_spray": ScenarioGuide(
        "Ataque real (password spray) COM sucesso - escalar",
        "Real attack (password spray) WITH a success - escalate",
        "Um IP externo tentou poucas senhas em muitas contas, e uma delas (l.taylor) conseguiu entrar sem nenhuma "
        "falha antes. É o padrão clássico de spray que achou uma senha válida: possível comprometimento.",
        "An external IP tried a few passwords across many accounts, and one of them (l.taylor) logged in with no "
        "prior failures. This is the classic pattern of a spray that found a valid password: possible compromise.",
        ("Escalated",)),
    "simulated_credential_compromise": ScenarioGuide(
        "Possível conta comprometida - escalar",
        "Possible account compromise - escalate",
        "Várias falhas seguidas de um login com sucesso pela VPN, à noite e de um IP externo novo. "
        "Precisa confirmar com o usuário e escalar.",
        "Several failures followed by a successful VPN logon, in the evening and from a new external IP. "
        "Needs confirming with the user and escalating.",
        ("Escalated",)),
    "ambiguous_rapid_source_change": ScenarioGuide(
        "Incerto - verificar com o usuário",
        "Uncertain - verify with the user",
        "Dois logins de IPs externos diferentes em poucos minutos. Pode ser troca de rede (Wi-Fi para 4G, VPN) ou "
        "uso indevido da conta. Os dados sozinhos não decidem: é preciso falar com o usuário.",
        "Two logons from different external IPs a few minutes apart. It may be a network change (Wi-Fi to 4G, VPN) "
        "or misuse of the account. The data alone cannot decide: you need to speak to the user.",
        ("In Progress", "Escalated")),
    "benign_forgotten_password": ScenarioGuide(
        "Benigno - usuário esqueceu a senha nova",
        "Benign - user forgot their new password",
        "A conta trocou a senha recentemente, errou várias vezes, foi bloqueada e o service desk desbloqueou. "
        "O alerta funcionou certo, mas a atividade é legítima: verdadeiro positivo benigno. Confirme o ticket.",
        "The account changed its password recently, failed several times, was locked out and the service desk "
        "unlocked it. The alert worked correctly but the activity is legitimate: a benign true positive. "
        "Confirm the ticket.",
        ("Closed - Benign True Positive",)),
    "benign_authorised_scan": ScenarioGuide(
        "Benigno - varredura autorizada",
        "Benign - authorised scan",
        "Um IP interno testou logins em várias contas: é o scanner de vulnerabilidades autorizado. "
        "Confirme a agenda da varredura com a equipe responsável antes de fechar.",
        "An internal IP tried logons against several accounts: it is the authorised vulnerability scanner. "
        "Confirm the scan schedule with the responsible team before closing.",
        ("Closed - Benign True Positive",)),
    "benign_on_call_engineer": ScenarioGuide(
        "Benigno - engenheiro de plantão",
        "Benign - on-call engineer",
        "Login de madrugada de um IP novo (um hotel), mas o funcionário estava de plantão. "
        "Confirme a escala de plantão antes de fechar.",
        "Night-time logon from a new IP (a hotel), but the employee was on call. "
        "Confirm the on-call rota before closing.",
        ("Closed - Benign True Positive",)),
    "benign_service_account_expired": ScenarioGuide(
        "Benigno - conta de serviço com senha expirada",
        "Benign - service account with an expired password",
        "A conta svc_backup tentou de madrugada com uma senha expirada, por duas noites. Não é ataque, é "
        "configuração errada: abra um ticket para a equipe atualizar a senha.",
        "The svc_backup account retried at night with an expired password, for two nights. Not an attack, it is "
        "a misconfiguration: raise a ticket for the team to update the password.",
        ("Closed - Benign True Positive",)),
    "normal": ScenarioGuide(
        "Falso positivo - atividade normal",
        "False positive - normal activity",
        "Os eventos por trás deste alerta são atividade normal do dia a dia. A regra disparou sem motivo real.",
        "The events behind this alert are normal day-to-day activity. The rule fired with no real cause.",
        ("Closed - False Positive",)),
}

STATUS_EXPLANATIONS = {
    "pt": [
        ("Closed - True Positive", "Era um ataque de verdade e o alerta pegou certo."),
        ("Closed - Benign True Positive", "O alerta disparou corretamente, mas a atividade era legítima "
                                          "(ex.: scanner autorizado, senha esquecida)."),
        ("Closed - False Positive", "O alerta disparou sem motivo: não havia nada do que a regra procura."),
        ("Escalated", "Passou para o nível 2 porque pode ser um incidente real e precisa de mais investigação."),
        ("In Progress", "Você ainda está verificando, por exemplo esperando o usuário responder."),
    ],
    "en": [
        ("Closed - True Positive", "It was a real attack and the alert was right."),
        ("Closed - Benign True Positive", "The alert fired correctly, but the activity was legitimate "
                                          "(e.g. authorised scanner, forgotten password)."),
        ("Closed - False Positive", "The alert fired with no reason: nothing the rule looks for was present."),
        ("Escalated", "Handed to Tier 2 because it may be a real incident and needs deeper investigation."),
        ("In Progress", "You are still checking, for example waiting for the user to reply."),
    ],
}


def load_ground_truth(path: Path) -> dict[str, str]:
    """Read a ground-truth CSV (event_id, scenario) into a dict. Missing file -> empty dict."""
    if not path.exists():
        return {}
    frame = pd.read_csv(path, dtype=str).drop_duplicates("event_id", keep="first")
    return dict(zip(frame["event_id"], frame["scenario"]))


def scenario_for_alert(alert: Alert, truth: dict[str, str]) -> str | None:
    """Most common non-normal scenario among the alert's evidence, 'normal' if all are normal, None if unknown."""
    labels = [truth[eid] for eid in alert.evidence_event_ids if eid in truth]
    if not labels:
        return None
    interesting = Counter(label for label in labels if label not in NOT_ATTACK_SCENARIOS)
    return interesting.most_common(1)[0][0] if interesting else "normal"


# ---------------------------------------------------------------------------
# Reference answers
# ---------------------------------------------------------------------------
def _duration(start: pd.Timestamp, end: pd.Timestamp, lang: str) -> str:
    seconds = int((end - start).total_seconds())
    hours, rest = divmod(seconds, 3600)
    minutes = rest // 60
    if hours:
        return f"{hours} h {minutes} min"
    return f"{minutes} min" if minutes else ("menos de 1 min" if lang == "pt" else "under 1 min")


def _findings(report: InvestigationReport, *prefixes: str) -> list[str]:
    return [f for f in report.context_findings if f.startswith(prefixes)]


def reference_answers(question_id: str, alert: Alert, report: InvestigationReport, config: dict,
                      lang: str = "pt") -> list[str]:
    """Reference points for one question, built only from the alert, the report and the data."""
    pt = lang == "pt"
    ctx = DetectionContext.from_config(config)
    evidence = report.evidence
    playbook = report.playbook

    if question_id == "rule":
        rule = f"{alert.rule_id} - {alert.rule_name}" + (f" ({alert.pattern})" if alert.pattern else "")
        return [rule, alert.trigger_reason]

    if question_id == "scope":
        none = "nenhuma" if pt else "none"
        return [
            f"{'Contas' if pt else 'Accounts'}: {', '.join(alert.usernames) or none}",
            f"{'IPs de origem' if pt else 'Source IPs'}: {', '.join(alert.source_ips) or none}",
            f"{'Máquinas' if pt else 'Hosts'}: {', '.join(alert.hostnames) or none}",
            f"{'Período' if pt else 'Window'}: {format_timestamp(alert.first_seen)} → {format_timestamp(alert.last_seen)}"
            f" ({_duration(alert.first_seen, alert.last_seen, lang)})",
        ]

    if question_id == "counts":
        failures = evidence[(evidence["event_type"] == EventType.LOGON) & (evidence["result"] == Result.FAILURE)]
        if failures.empty:
            return ["Nenhuma falha de login nas evidências deste alerta." if pt
                    else "No failed logons in this alert's evidence."]
        span = _duration(failures["timestamp"].min(), failures["timestamp"].max(), lang)
        accounts = failures["username"].nunique()
        reasons = ", ".join(f"{r} ({n})" for r, n in failures["failure_reason"].value_counts().items() if r)
        line = (f"{len(failures)} falha(s) contra {accounts} conta(s) em {span}." if pt
                else f"{len(failures)} failure(s) against {accounts} account(s) over {span}.")
        return [line] + ([f"{'Motivos' if pt else 'Reasons'}: {reasons}"] if reasons else [])

    if question_id == "success":
        lines = _findings(report, "Successful logon", "No successful logon")
        wins = evidence[(evidence["event_type"] == EventType.LOGON) & (evidence["result"] == Result.SUCCESS)]
        for _, row in wins.iterrows():
            lines.append((f"Sucesso nas evidências: {row['username']} de {row['source_ip']} às "
                          if pt else f"Success in the evidence: {row['username']} from {row['source_ip']} at ")
                         + format_timestamp(row["timestamp"]))
        return lines

    if question_id == "source":
        lines = [f"{ip}: {'interno' if ctx.is_internal(ip) else 'externo'}" if pt
                 else f"{ip}: {ctx.classify_ip(ip)}" for ip in alert.source_ips]
        return lines + _findings(report, "Source ")

    if question_id == "time":
        lines = []
        for label, ts in ((("Início" if pt else "Start"), alert.first_seen), (("Fim" if pt else "End"), alert.last_seen)):
            inside = ctx.is_business_hours(ts)
            day = (WEEKDAYS_PT[ts.weekday()] if pt else ts.strftime("%A"))
            where = ("dentro do horário comercial" if inside else "FORA do horário comercial") if pt else \
                    ("within business hours" if inside else "OUTSIDE business hours")
            lines.append(f"{label}: {format_timestamp(ts)} ({day}) - {where}")
        return lines

    if question_id == "account_events":
        counts = evidence["event_type"].value_counts()
        lines = [f"{kind}: {int(counts[kind])}" for kind in
                 (EventType.ACCOUNT_LOCKOUT, EventType.ACCOUNT_UNLOCK, EventType.PASSWORD_CHANGE) if kind in counts]
        lines += _findings(report, "Password change", "Account unlock", "A later password change")
        return lines or (["Nenhum bloqueio, desbloqueio ou troca de senha relacionado." if pt
                          else "No related lockout, unlock or password change."])

    if question_id == "account_type":
        service = [u for u in alert.usernames if ctx.is_service_account(u)]
        others = [u for u in alert.usernames if not ctx.is_service_account(u)]
        lines = []
        if service:
            lines.append(f"{'Conta(s) de serviço' if pt else 'Service account(s)'}: {', '.join(service)}")
        if others:
            lines.append((f"{len(others)} conta(s) de usuário (não são de serviço): " if pt
                          else f"{len(others)} user account(s) (not service accounts): ") + ", ".join(others))
        lines += _findings(report, "Account name(s) with no successful logon")
        return lines or (["O alerta é sobre um IP, não uma conta específica." if pt
                          else "The alert is about an IP address, not a specific account."])

    if question_id == "benign":
        return (playbook.benign_explanations + playbook.false_positive_considerations
                + [f"{'Indicador benigno encontrado' if pt else 'Benign indicator found'}: {b}"
                   for b in report.benign_indicators])

    if question_id == "missing":
        return list(playbook.investigation_steps)

    if question_id == "verdict":
        return [report.conclusion]

    if question_id == "severity":
        return [f"{alert.severity.value}: {alert.severity_reason}" if alert.severity_reason else alert.severity.value]

    if question_id == "mitre":
        return [alert.mitre_attack or ("Sem mapeamento" if pt else "Not mapped")]

    if question_id == "action":
        return list(playbook.containment_actions)

    if question_id == "summary":
        return [report.conclusion] + alert.observed_facts[:3]

    raise KeyError(f"Unknown question: {question_id}")


# ---------------------------------------------------------------------------
# Saving answers and exporting them
# ---------------------------------------------------------------------------
def dataset_token(source_name: str) -> str:
    """Filesystem- and widget-key-safe identifier for a dataset."""
    return re.sub(r"[^A-Za-z0-9]+", "_", source_name).strip("_").lower() or "dataset"


def answers_path(base_dir: Path, source_name: str, alert_id: str) -> Path:
    return base_dir / f"{dataset_token(source_name)}__{alert_id}.json"


def load_progress(path: Path) -> dict:
    """Saved answers, status and reveal flag for one alert. Unreadable or missing file -> empty progress."""
    empty = {"answers": {}, "status": None, "revealed": False}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return empty
    if not isinstance(data, dict):
        return empty
    answers = data.get("answers") if isinstance(data.get("answers"), dict) else {}
    return {"answers": {k: str(v) for k, v in answers.items() if k in QUESTION_IDS},
            "status": data.get("status"), "revealed": bool(data.get("revealed", False))}


def save_progress(path: Path, answers: dict[str, str], status: str | None, revealed: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"answers": {k: v for k, v in answers.items() if k in QUESTION_IDS and v.strip()},
               "status": status, "revealed": revealed,
               "updated": pd.Timestamp.now(tz="UTC").floor("s").isoformat()}
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def answered_count(answers: dict[str, str]) -> int:
    return sum(1 for qid in QUESTION_IDS if answers.get(qid, "").strip())


def answers_to_markdown(answers: dict[str, str], lang: str = "pt") -> str:
    """Analyst triage answers formatted for the 'Analyst notes' section of the report."""
    blocks = []
    for stage in STAGES:
        stage_lines = []
        for question in questions_for_stage(stage.id):
            answer = answers.get(question.id, "").strip()
            if answer:
                stage_lines.append(f"**{question.text(lang)}**\n\n{answer}")
        if stage_lines:
            blocks.append(f"### {stage.pt if lang == 'pt' else stage.en}\n\n" + "\n\n".join(stage_lines))
    return "\n\n".join(blocks)
