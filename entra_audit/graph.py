"""Read-only Microsoft Graph collection, pagination, retries and validation."""
import time
from datetime import datetime, timezone
from urllib.parse import quote, urlsplit

import requests

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
RETRY_STATUS = {429, 500, 502, 503, 504}


class GraphClient:
    def __init__(self, token, session=None, max_attempts=4, sleep=time.sleep):
        self.session = session or requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        })
        self.max_attempts = max_attempts
        self.sleep = sleep

    @staticmethod
    def validate_url(url):
        parsed = urlsplit(url)
        if parsed.scheme != "https" or parsed.hostname != "graph.microsoft.com" or parsed.port not in (None, 443):
            raise ValueError("Refusing unexpected Microsoft Graph pagination URL")
        if not parsed.path.startswith("/v1.0/"):
            raise ValueError("Refusing Graph URL outside /v1.0/")
        if parsed.username or parsed.password or parsed.fragment:
            raise ValueError("Unexpected Graph URL components")
        return url

    def request_json(self, url):
        self.validate_url(url)
        for attempt in range(self.max_attempts):
            response = self.session.get(url, timeout=30)
            if response.status_code in RETRY_STATUS and attempt < self.max_attempts - 1:
                raw = response.headers.get("Retry-After", "")
                delay = min(int(raw), 60) if raw.isdecimal() else min(2 ** attempt, 30)
                self.sleep(delay)
                continue
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict) or not isinstance(payload.get("value"), list):
                raise ValueError("Unexpected Graph response shape")
            return payload
        raise RuntimeError("Microsoft Graph retries exhausted")

    def pages(self, url):
        seen = set()
        while url:
            if url in seen:
                raise ValueError("Repeated pagination URL; aborting")
            seen.add(url)
            page = self.request_json(url)
            yield from page["value"]
            url = page.get("@odata.nextLink")


def collect_snapshot(client, tenant_id, group_prefix="sg-lab-"):
    """Fail closed: a failed collection does not result in a partial audit report."""
    users_url = (
        f"{GRAPH_BASE}/users?$select=id,displayName,userPrincipalName,"
        "department,jobTitle,accountEnabled&$top=999"
    )
    groups_url = f"{GRAPH_BASE}/groups?$select=id,displayName,securityEnabled&$top=999"
    users = list(client.pages(users_url))
    groups = list(client.pages(groups_url))
    matching_groups = [
        group for group in groups
        if group.get("displayName", "").casefold().startswith(group_prefix.casefold())
    ]
    matching_groups.sort(key=lambda g: (g.get("displayName") or "").casefold())
    memberships = {}
    for group in matching_groups:
        encoded_id = quote(group["id"], safe="")
        memberships[group["id"]] = list(
            client.pages(f"{GRAPH_BASE}/groups/{encoded_id}/members")
        )
    return {
        "source": "live",
        "tenant_id": tenant_id,
        "collected_at_utc": datetime.now(timezone.utc).isoformat(),
        "membership_scope": "direct",
        "group_prefix": group_prefix,
        "users": users,
        "groups": groups,
        "memberships": memberships,
    }
