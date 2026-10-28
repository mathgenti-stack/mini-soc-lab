"""Environment knowledge the rules need: which networks are internal, what business hours are."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from functools import lru_cache

import pandas as pd

from ..i18n import Msg


@dataclass(frozen=True)
class DetectionContext:
    internal_networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    business_start_hour: int
    business_end_hour: int
    business_weekdays: frozenset[int]
    service_account_prefixes: tuple[str, ...] = ("svc_",)

    @classmethod
    def from_config(cls, config: dict) -> "DetectionContext":
        env = config["environment"]
        hours = env["business_hours"]
        return cls(
            internal_networks=tuple(ipaddress.ip_network(net, strict=False) for net in env["internal_networks"]),
            business_start_hour=int(hours["start_hour"]),
            business_end_hour=int(hours["end_hour"]),
            business_weekdays=frozenset(hours.get("weekdays", [0, 1, 2, 3, 4])),
            service_account_prefixes=tuple(env.get("service_account_prefixes", ["svc_"])),
        )

    def is_internal(self, ip: str) -> bool:
        address = _parse_ip(ip)
        return address is not None and any(address in network for network in self.internal_networks)

    def classify_ip(self, ip: str) -> Msg:
        if _parse_ip(ip) is None:
            return Msg("ip.unparseable")
        return Msg("ip.internal") if self.is_internal(ip) else Msg("ip.external")

    def is_business_hours(self, ts: pd.Timestamp) -> bool:
        return ts.weekday() in self.business_weekdays and self.business_start_hour <= ts.hour < self.business_end_hour

    def is_service_account(self, username: str) -> bool:
        return username.startswith(self.service_account_prefixes)


@lru_cache(maxsize=4096)
def _parse_ip(ip: str):
    try:
        return ipaddress.ip_address(ip)
    except ValueError:
        return None
