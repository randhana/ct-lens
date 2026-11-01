"""Security findings from public CT data only (README §3.4).

Three detectors, all working purely from certificate metadata we already have —
no target is ever contacted:

1. **Lookalike / typosquat** — domains that imitate a brand or a high-volume
   legitimate domain via character edits or homoglyphs (``bankofceyl0n.lk``).
2. **Exposed internal / staging hostnames** — hostnames that leak internal
   infrastructure (``vpn-staging.internal.example.lk``) into public CT logs.
3. **Suspicious issuance** — certificates signed by a non-public / self-signed
   issuer, which is unusual for a normally CA-issued domain.

Responsible disclosure is built in (README §5/§6): every :class:`Finding` can
be :meth:`~Finding.anonymized`, masking the organisation so aggregate output
never names a specific party.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, replace

from ct_lens.core.models import Certificate

# --------------------------------------------------------------------------- #
# Configuration / heuristics
# --------------------------------------------------------------------------- #

#: Tokens that strongly suggest a non-public, internal or pre-production host.
DEFAULT_EXPOSED_TOKENS: frozenset[str] = frozenset(
    {
        "internal",
        "intranet",
        "corp",
        "local",
        "localhost",
        "staging",
        "stage",
        "uat",
        "qa",
        "test",
        "testing",
        "dev",
        "devel",
        "vpn",
        "admin",
        "jenkins",
        "gitlab",
        "jira",
        "confluence",
        "grafana",
        "kibana",
        "backup",
        "db",
        "database",
        "sql",
        "mail-internal",
        "sso-test",
    }
)

#: Second-level labels that are public suffixes under many ccTLDs (e.g. gov.lk,
#: com.lk). Used to find the real "organisation" label in a hostname.
_PUBLIC_2LD: frozenset[str] = frozenset(
    {"com", "co", "gov", "org", "net", "edu", "ac", "sch", "mil", "or", "ne", "go"}
)

#: Common homoglyph / confusable substitutions used in typosquatting.
_CONFUSABLES: dict[str, str] = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "6": "g",
    "7": "t",
    "8": "b",
    "9": "g",
    "$": "s",
    "@": "a",
    "|": "l",
}

#: Rank used to sort findings (most severe first).
_SEVERITY_ORDER: dict[str, int] = {"high": 0, "medium": 1, "low": 2, "info": 3}


@dataclass(frozen=True, slots=True)
class Finding:
    """A single security finding derived from a certificate."""

    category: str  # "lookalike" | "exposed-host" | "suspicious-issuance"
    severity: str  # "high" | "medium" | "low" | "info"
    domain: str
    summary: str
    cert_id: int
    issuer: str
    reference: str | None = None  # e.g. the brand/label a lookalike imitates

    def anonymized(self) -> Finding:
        """Return a copy with the organisation label masked (for publishing)."""
        return replace(
            self,
            domain=_mask_domain(self.domain),
            reference=_mask_label(self.reference) if self.reference else None,
        )


# --------------------------------------------------------------------------- #
# Small string helpers
# --------------------------------------------------------------------------- #


def levenshtein(a: str, b: str) -> int:
    """Classic edit distance between two strings (iterative DP, O(len(a)*len(b)))."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost))
        previous = current
    return previous[-1]


def defang_confusables(label: str) -> str:
    """Normalise common homoglyphs so ``bankofceyl0n`` -> ``bankofceylon``."""
    return "".join(_CONFUSABLES.get(ch, ch) for ch in label.lower())


def registrable_label(domain: str) -> str:
    """Best-effort "organisation" label of a hostname (no public-suffix list).

    ``www.bankofceylon.lk`` -> ``bankofceylon``;
    ``mail.treasury.gov.lk`` -> ``treasury`` (``gov`` is a public 2LD).
    """
    host = domain.lstrip("*.").strip(".").lower()
    parts = [p for p in host.split(".") if p]
    if len(parts) < 2:
        return host
    # parts[-1] is the TLD; the org label is normally parts[-2], unless that is
    # a public second-level label (gov/com/...), in which case go one deeper.
    if len(parts) >= 3 and parts[-2] in _PUBLIC_2LD:
        return parts[-3]
    return parts[-2]


def _mask_label(label: str) -> str:
    """Mask an organisation label: ``bankofceylon`` -> ``b***``."""
    label = label.strip()
    if len(label) <= 1:
        return "***"
    return f"{label[0]}***"


def _mask_domain(domain: str) -> str:
    """Mask only the organisation label within a hostname, keeping its shape."""
    org = registrable_label(domain)
    if not org:
        return domain
    return domain.replace(org, _mask_label(org), 1)


# --------------------------------------------------------------------------- #
# Detectors
# --------------------------------------------------------------------------- #


def detect_lookalikes(
    certificates: list[Certificate],
    *,
    brands: list[str] | None = None,
    anchor_count: int = 25,
    max_distance: int = 1,
) -> list[Finding]:
    """Flag domains that imitate a brand or a high-volume legitimate label.

    Reference labels = any caller-supplied ``brands`` plus the most frequent
    organisation labels in the dataset (treated as likely-legitimate anchors).
    A domain is a lookalike if its label is *close but not equal* to a reference
    label — either within ``max_distance`` edits, or identical after homoglyph
    normalisation.
    """
    label_counts: Counter[str] = Counter()
    for cert in certificates:
        for domain in cert.domains:
            label_counts[registrable_label(domain)] += 1

    brand_set: set[str] = {b.lower() for b in (brands or [])}
    # Reference ("legitimate") labels: supplied brands + the most frequent labels
    # in the dataset, which are the likely-genuine, high-volume organisations.
    references: set[str] = set(brand_set)
    references.update(label for label, _ in label_counts.most_common(anchor_count))
    references.discard("")

    findings: list[Finding] = []
    seen: set[tuple[int, str]] = set()
    for cert in certificates:
        for domain in cert.domains:
            label = registrable_label(domain)
            # The real brand itself is never a lookalike of itself.
            if not label or label in brand_set:
                continue
            match = _closest_reference(label, references, max_distance)
            if match is None:
                continue
            # Only flag the *rarer* label as imitating the reference, unless the
            # reference is an explicitly protected brand. This avoids flagging a
            # legitimate high-volume domain and double-flagging a squat pair.
            if match not in brand_set and label_counts[label] >= label_counts[match]:
                continue
            key = (cert.cert_id, domain)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    category="lookalike",
                    severity="high",
                    domain=domain,
                    summary=f"Possible lookalike of '{match}'",
                    cert_id=cert.cert_id,
                    issuer=cert.issuer,
                    reference=match,
                )
            )
    return findings


def _closest_reference(label: str, references: set[str], max_distance: int) -> str | None:
    """Return a reference label this one imitates, or ``None``."""
    defanged = defang_confusables(label)
    for reference in references:
        if reference == label:
            continue
        # Homoglyph match (e.g. 0 -> o) OR a small edit distance.
        if defanged == defang_confusables(reference):
            return reference
        if abs(len(label) - len(reference)) <= max_distance and (
            levenshtein(label, reference) <= max_distance
        ):
            return reference
    return None


def detect_exposed_hosts(
    certificates: list[Certificate],
    *,
    tokens: frozenset[str] = DEFAULT_EXPOSED_TOKENS,
) -> list[Finding]:
    """Flag hostnames whose labels leak internal/staging infrastructure."""
    findings: list[Finding] = []
    seen: set[tuple[int, str]] = set()
    for cert in certificates:
        for domain in cert.domains:
            labels = set(domain.lstrip("*.").lower().split("."))
            hit = labels & tokens
            if not hit:
                continue
            key = (cert.cert_id, domain)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    category="exposed-host",
                    severity="medium",
                    domain=domain,
                    summary=f"Internal/staging hostname exposed (token: {sorted(hit)[0]})",
                    cert_id=cert.cert_id,
                    issuer=cert.issuer,
                )
            )
    return findings


def _has_issuer_organization(issuer_name: str) -> bool:
    """True if the issuer DN contains an ``O=`` component (public CAs always do)."""
    return any(part.strip().upper().startswith("O=") for part in issuer_name.split(","))


def detect_suspicious_issuance(certificates: list[Certificate]) -> list[Finding]:
    """Flag certificates signed by a non-public / self-signed issuer.

    Public CAs always carry an ``O=`` organisation in their issuer DN. Its
    absence is a strong signal of a self-signed or private issuer appearing in
    the logs for a public-looking domain.
    """
    findings: list[Finding] = []
    for cert in certificates:
        if _has_issuer_organization(cert.issuer_name):
            continue
        findings.append(
            Finding(
                category="suspicious-issuance",
                severity="low",
                domain=cert.common_name or (cert.domains[0] if cert.domains else ""),
                summary="Certificate issued by a non-public / self-signed CA",
                cert_id=cert.cert_id,
                issuer=cert.issuer,
            )
        )
    return findings


def find_all(
    certificates: list[Certificate],
    *,
    brands: list[str] | None = None,
    anonymize: bool = False,
) -> list[Finding]:
    """Run every detector and return findings, most severe first.

    Args:
        certificates: The dataset to scan.
        brands: Optional brand/institution labels to protect from lookalikes.
        anonymize: When ``True`` (the safe default for publishing), mask the
            organisation in every finding.
    """
    findings = (
        detect_lookalikes(certificates, brands=brands)
        + detect_exposed_hosts(certificates)
        + detect_suspicious_issuance(certificates)
    )
    findings.sort(key=lambda f: (_SEVERITY_ORDER.get(f.severity, 99), f.category, f.domain))
    if anonymize:
        findings = [f.anonymized() for f in findings]
    return findings
