from datetime import datetime
from zoneinfo import ZoneInfo

import pytest

from vulnscan.scope import Scope, ScopeGuard

JST = ZoneInfo("Asia/Tokyo")

SCOPE = {
    "owner": "sec@example.com",
    "authorizations": [
        {
            "id": "AUTH-1",
            "approved_by": "部長",
            "valid_from": "2026-10-01",
            "valid_until": "2027-03-31",
            "targets": {
                "cidrs": ["10.0.10.0/24"],
                "domains": ["app.example.com", "*.stg.example.com"],
                "urls": ["https://app.example.com/"],
            },
            "exclusions": ["10.0.10.1", "https://app.example.com/admin/", "db.stg.example.com"],
            "allowed_profiles": ["passive", "standard"],
            "time_window": "Mon-Fri 22:00-06:00",
            "rate_limit": {"rps": 7, "concurrency": 3},
        }
    ],
}

# 2026-10-07 は水曜日
WED_NIGHT = datetime(2026, 10, 7, 23, 0, tzinfo=JST)


def fake_resolver(table):
    def resolve(host):
        if host not in table:
            raise OSError("not found")
        return table[host]

    return resolve


@pytest.fixture
def scope():
    return Scope.from_dict(SCOPE)


@pytest.fixture
def guard(scope):
    return ScopeGuard(
        scope,
        resolver=fake_resolver(
            {
                "app.example.com": ["10.0.10.5"],
                "web.stg.example.com": ["10.0.10.6"],
                "evil.stg.example.com": ["203.0.113.9"],
                "rtr.stg.example.com": ["10.0.10.1"],
            }
        ),
        clock=lambda: WED_NIGHT,
    )
