"""Analyst guidance for each rule: benign explanations, false-positive notes and next steps.

Kept separate from the detection logic so guidance can be edited without touching rules.
All recommended actions are for a junior analyst to propose or perform through the
organisation's normal processes - this tool never acts on real systems.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Playbook:
    description: str
    benign_explanations: list[str]
    false_positive_considerations: list[str]
    investigation_steps: list[str]
    containment_actions: list[str]
    limitations: list[str]


COMMON_LIMITATIONS = [
    "Analysis is limited to the authentication events in this dataset; endpoint, email, proxy and EDR telemetry "
    "were not available.",
    "Source IP addresses do not identify a person. Addresses can be shared (NAT, VPN, proxies) or spoofed upstream.",
    "No threat-intelligence or geolocation enrichment was performed.",
    "Timestamps are treated as UTC as recorded; clock drift between log sources was not assessed.",
]

PLAYBOOKS: dict[str, Playbook] = {
    "R001": Playbook(
        description="Detects bursts of failed logons against a single account within a short sliding window.",
        benign_explanations=[
            "The user forgot or recently changed their password and kept retrying.",
            "A phone, mapped drive or saved credential is still using an old password.",
            "Caps Lock or keyboard layout issues during interactive logon.",
        ],
        false_positive_considerations=[
            "Check for a recent PASSWORD_CHANGE or service desk ticket for the account.",
            "Internal source addresses that match the user's usual workstation lower the likelihood of an attack.",
            "Thresholds that are too low will alert on ordinary typos; too high will miss slow guessing.",
        ],
        investigation_steps=[
            "Confirm whether the source address is the user's usual workstation or VPN address.",
            "Check whether any successful logon for the account followed the failures (see rule R002).",
            "Check whether the same source address targeted other accounts (see rule R004).",
            "Contact the account owner through a known-good channel to confirm whether they were attempting to log on.",
        ],
        containment_actions=[
            "If the activity is unexplained and from an external address, propose blocking the address at the VPN "
            "or firewall through the change process.",
            "If the account owner did not make the attempts, request a password reset and MFA review.",
        ],
        limitations=[
            "Slow guessing spread over longer than the window will not trigger this rule.",
            "Attempts against many accounts with few tries each are covered by R004, not R001.",
        ],
    ),
    "R002": Playbook(
        description="Detects a successful logon that follows several failures for the same account.",
        benign_explanations=[
            "The user mistyped their password a few times and then entered it correctly.",
            "The user changed their password and a device kept using the old one until it was updated.",
        ],
        false_positive_considerations=[
            "Failures and success from the same internal workstation are usually user error.",
            "Failures from one external address followed by success from that same address warrant priority review.",
            "Successes after service desk unlocks are expected and should be checked against tickets.",
        ],
        investigation_steps=[
            "Compare the source address of the failures with the source of the success.",
            "Review all activity for the account after the successful logon (hosts accessed, session length).",
            "Check whether the source address appears in other alerts.",
            "Verify with the account owner whether they logged on at that time.",
        ],
        containment_actions=[
            "If the owner did not log on, escalate to a senior analyst, propose disabling the account or resetting "
            "the password, and revoke active sessions through the identity team.",
        ],
        limitations=[
            "Only failures within the lookback window are counted; a success after a long pause is not linked.",
            "The rule cannot tell whether the same person made the failures and the success.",
        ],
    ),
    "R003": Playbook(
        description="Detects entities (source addresses or accounts) with an abnormally high daily failure rate.",
        benign_explanations=[
            "A service account or scheduled task is using an expired or wrong password.",
            "Authorised vulnerability scanning or penetration testing.",
            "A misconfigured application retrying authentication in a loop.",
        ],
        false_positive_considerations=[
            "Service account names (e.g. the 'svc_' prefix) and regular retry intervals suggest automation.",
            "Check scan schedules and change tickets for internal scanner addresses.",
            "The minimum attempts setting prevents one failure in one attempt from being reported as 100%.",
        ],
        investigation_steps=[
            "Identify the owner of the account or the system behind the source address.",
            "Look at the timing of the failures: regular intervals point to automation.",
            "Check whether the failure reasons are consistent (e.g. all EXPIRED_PASSWORD).",
        ],
        containment_actions=[
            "For misconfigured services, raise a ticket with the system owner to update the credential.",
            "For unexplained external sources, propose blocking the address through the change process.",
        ],
        limitations=[
            "Rates are calculated per calendar day (UTC), so activity spanning midnight is split.",
            "Low-volume activity below the minimum attempts setting is ignored.",
        ],
    ),
    "R004": Playbook(
        description="Detects a single source address failing to log on to many different accounts.",
        benign_explanations=[
            "An authorised vulnerability scanner testing default credentials.",
            "Many users behind one shared NAT, proxy or VPN address after a password policy change.",
            "A misconfigured application cycling through a list of accounts.",
        ],
        false_positive_considerations=[
            "Internal scanner addresses should be on a documented allow list; confirm the scan window.",
            "A high proportion of UNKNOWN_USER failures suggests enumeration or default-account testing.",
            "A successful logon from the same address for one of the targeted accounts changes the priority sharply.",
        ],
        investigation_steps=[
            "Determine whether the source address is internal, a known scanner, or a shared gateway.",
            "List which targeted accounts exist and whether any logged on successfully from the address.",
            "For any successful account, review its subsequent activity and contact its owner.",
            "Search for the same address in other alerts and earlier logs.",
        ],
        containment_actions=[
            "For an external source with a successful logon, escalate immediately and propose resetting the affected "
            "account's password and revoking sessions.",
            "Propose blocking the external address at the perimeter through the change process.",
        ],
        limitations=[
            "Distributed spraying from many addresses will not trigger this rule.",
            "Shared addresses make it impossible to attribute activity to a single device from logs alone.",
        ],
    ),
    "R005:lockout_then_success": Playbook(
        description="Detects a successful logon shortly after the same account was locked out.",
        benign_explanations=[
            "The service desk unlocked the account after the user forgot their password.",
            "The lockout expired automatically and the user then remembered their password.",
        ],
        false_positive_considerations=[
            "An ACCOUNT_UNLOCK event from a service desk workstation before the success supports a benign explanation.",
            "A success from a different, external address than usual does not.",
        ],
        investigation_steps=[
            "Check for a service desk ticket matching the unlock time.",
            "Compare the source of the success with the source of the failures that caused the lockout.",
            "Confirm with the user that the successful logon was theirs.",
        ],
        containment_actions=[
            "If the user did not log on, escalate and propose a password reset with MFA re-registration.",
        ],
        limitations=["Lockouts are only visible if the domain controller events are included in the dataset."],
    ),
    "R005:off_hours_new_source": Playbook(
        description="Detects a successful logon outside business hours from an address never seen for the account.",
        benign_explanations=[
            "On-call or overtime work.",
            "The user is travelling, working from a hotel, or using a new home router or mobile hotspot.",
        ],
        false_positive_considerations=[
            "IT and on-call staff routinely log on out of hours; check the on-call rota.",
            "The baseline only covers this dataset, so a 'new' address may simply be one not seen recently.",
        ],
        investigation_steps=[
            "Check whether the user is on call or has reported travel.",
            "Review what the session accessed after the logon.",
            "Confirm with the user through a known-good channel.",
        ],
        containment_actions=["None by default; escalate only if the user does not recognise the activity."],
        limitations=[
            "Business hours are configured in UTC and do not account for UK daylight saving time or shift patterns.",
            "Activity in the baseline learning period is not alerted on.",
        ],
    ),
    "R005:rapid_source_change": Playbook(
        description="Detects successful logons for one account from two external addresses within minutes.",
        benign_explanations=[
            "Switching between home broadband and a mobile hotspot.",
            "A VPN client or mobile carrier changing the public address.",
        ],
        false_positive_considerations=[
            "Both addresses being in residential or mobile ranges is common for remote workers.",
            "Without geolocation the rule cannot judge whether travel between the two locations is possible.",
        ],
        investigation_steps=[
            "Check whether both addresses have been used by the account before.",
            "Determine whether both sessions were active at the same time (no logoff in between).",
            "Confirm with the user which devices and networks they were using.",
        ],
        containment_actions=["If the user recognises only one session, escalate and propose revoking all sessions."],
        limitations=["No geolocation or ASN data is available in this lab."],
    ),
}


def get_playbook(key: str) -> Playbook:
    return PLAYBOOKS.get(key) or PLAYBOOKS[key.split(":")[0]]
