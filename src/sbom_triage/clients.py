"""Fixed HTTPS endpoints, bounded retries and explicit data-source failures."""

import math
import re
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import requests

OSV_URL = "https://api.osv.dev/v1/query"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_MIRROR_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


class SourceError(RuntimeError):
    """A source is unavailable or returned unusable evidence."""


def validate_record(record: dict) -> None:
    """Validate the OSV fields consumed downstream; fail the package lookup closed."""
    if not record["id"] or len(record["id"]) > 300:
        raise SourceError("Invalid OSV identifier.")
    for key in ("aliases", "severity", "affected", "references"):
        if not isinstance(record.get(key, []), list):
            raise SourceError(f"OSV {key} must be an array.")
    if any(not isinstance(alias, str) or not alias for alias in record.get("aliases", [])):
        raise SourceError("Invalid OSV aliases.")
    for key in ("summary", "modified", "withdrawn"):
        if key in record and not isinstance(record[key], str):
            raise SourceError(f"Invalid OSV {key}.")
    severities = list(record.get("severity", []))
    for affected in record.get("affected", []):
        if not isinstance(affected, dict) or not isinstance(affected.get("package", {}), dict):
            raise SourceError("Invalid OSV affected package.")
        package = affected.get("package", {})
        if any(not isinstance(value, str) for value in package.values()):
            raise SourceError("OSV package identity must contain strings.")
        if not isinstance(affected.get("severity", []), list):
            raise SourceError("Invalid package-specific severity.")
        severities.extend(affected.get("severity", []))
    for item in severities:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("score"), str)
            or not isinstance(item.get("type"), str)
        ):
            raise SourceError("Invalid OSV severity entry.")
    for ref in record.get("references", []):
        if not isinstance(ref, dict) or not isinstance(ref.get("url"), str):
            raise SourceError("Invalid OSV reference.")


class JsonHTTP:
    def __init__(self, session=None, sleeper=time.sleep):
        self.session = session or requests.Session()
        self.session.headers.update({"User-Agent": "sbom-triage/0.1 (educational portfolio)"})
        self.sleep = sleeper

    def close(self):
        self.session.close()

    def request(self, method: str, url: str, **kwargs) -> dict:
        for attempt in range(3):
            response = None
            try:
                response = self.session.request(
                    method, url, timeout=(5, 25), allow_redirects=False, **kwargs
                )
                if response.status_code == 429 or 500 <= response.status_code <= 599:
                    response.raise_for_status()
                if response.status_code != 200:
                    raise SourceError(f"HTTP {response.status_code} from {url}")
                data = response.json()
                if not isinstance(data, dict):
                    raise SourceError(f"Expected a JSON object from {url}")
                return data
            except (requests.Timeout, requests.ConnectionError, requests.HTTPError) as exc:
                if attempt == 2:
                    raise SourceError(f"Request failed after 3 attempts: {url}") from exc
                delay = float(2**attempt)
                if response is not None:
                    retry = response.headers.get("Retry-After")
                    if retry:
                        try:
                            delay = float(retry)
                        except ValueError:
                            try:
                                delay = (
                                    parsedate_to_datetime(retry) - datetime.now(timezone.utc)
                                ).total_seconds()
                            except (ValueError, TypeError, OverflowError):
                                delay = float(2**attempt)
                if not math.isfinite(delay) or delay > 30:
                    raise SourceError(
                        "Retry-After exceeds 30-second budget; retry the scan later."
                    ) from exc
                self.sleep(max(0, delay))
            except (requests.RequestException, ValueError) as exc:
                raise SourceError(f"Invalid response from {url}: {type(exc).__name__}") from exc
        raise SourceError("Request retry budget exhausted.")


class LiveSources:
    mode = "live"

    def __init__(self, http=None):
        self.http = http or JsonHTTP()
        self.provenance: dict = {}

    def close(self):
        self.http.close()

    def query(self, purl: str) -> list[dict]:
        records, seen_tokens = [], set()
        payload = {"package": {"purl": purl}}
        for _ in range(20):
            data = self.http.request("POST", OSV_URL, json=payload)
            vulns = data.get("vulns", [])
            if not isinstance(vulns, list) or any(
                not isinstance(v, dict) or not isinstance(v.get("id"), str) for v in vulns
            ):
                raise SourceError("OSV returned malformed vulnerability records.")
            for vulnerability in vulns:
                validate_record(vulnerability)
            records.extend(vulns)
            if len(records) > 10000:
                raise SourceError("OSV result exceeds safety limit.")
            token = data.get("next_page_token")
            if not token:
                self.provenance["osv"] = {"url": OSV_URL, "retrieved_at": now()}
                return records
            if not isinstance(token, str) or token in seen_tokens:
                raise SourceError("OSV returned an invalid or repeated page token.")
            seen_tokens.add(token)
            payload = {"package": {"purl": purl}, "page_token": token}
        raise SourceError("OSV pagination exceeds 20 pages; no partial result accepted.")

    def epss(self, cves: list[str]) -> tuple[dict, list[str]]:
        result, errors = {}, []
        # At most 50 CVEs AND 1,800 characters; FIRST's cve parameter allows 2,000.
        chunks, chunk = [], []
        for cve in sorted(set(cves)):
            if chunk and (len(chunk) == 50 or len(",".join(chunk + [cve])) > 1800):
                chunks.append(chunk)
                chunk = []
            chunk.append(cve)
        if chunk:
            chunks.append(chunk)
        for batch in chunks:
            try:
                data = self.http.request(
                    "GET", EPSS_URL, params={"cve": ",".join(batch), "limit": 100}
                )
                if data.get("status") != "OK" or not isinstance(data.get("data"), list):
                    raise SourceError("EPSS returned an invalid response envelope.")
                rows = data["data"]
                if int(data.get("total", len(rows))) > len(rows):
                    raise SourceError("EPSS response unexpectedly truncated.")
                validated = {}
                for row in rows:
                    cve = row["cve"]
                    score, percentile = float(row["epss"]), float(row["percentile"])
                    if cve not in batch or not 0 <= score <= 1 or not 0 <= percentile <= 1:
                        raise ValueError("Invalid EPSS value or CVE.")
                    date = row["date"]
                    datetime.strptime(date, "%Y-%m-%d")
                    validated[cve] = {"score": score, "percentile": percentile, "date": date}
                result.update(validated)
                self.provenance["epss"] = {"url": EPSS_URL, "retrieved_at": now()}
            except (SourceError, ValueError, KeyError, TypeError) as exc:
                errors.append(f"EPSS batch unavailable: {exc}")
        return result, errors

    def kev(self) -> dict:
        used_url, fallback_reason = KEV_URL, None
        try:
            data = self.http.request("GET", KEV_URL)
        except SourceError as exc:
            # CISA publishes this official mirror specifically for data consumers.
            used_url, fallback_reason = KEV_MIRROR_URL, str(exc)
            data = self.http.request("GET", KEV_MIRROR_URL)
        rows = data.get("vulnerabilities")
        if not isinstance(rows, list) or data.get("count") != len(rows):
            raise SourceError("CISA KEV feed is missing entries or has an invalid count.")
        if not isinstance(data.get("catalogVersion"), str) or not data.get("dateReleased"):
            raise SourceError("CISA KEV catalog metadata missing.")
        result = {}
        for row in rows:
            if not isinstance(row, dict) or not CVE_RE.fullmatch(str(row.get("cveID", ""))):
                raise SourceError("CISA KEV feed contains an invalid CVE.")
            result[row["cveID"]] = row
        self.provenance["kev"] = {
            "url": used_url,
            "fallback_reason": fallback_reason,
            "retrieved_at": now(),
            "catalog_version": data["catalogVersion"],
            "date_released": data["dateReleased"],
        }
        return result
