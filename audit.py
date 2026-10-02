#!/usr/bin/env python3
"""OCI cost and security posture audit CLI (offline, fixture-driven).

Reads an exported cost report (CSV) and a tenancy configuration snapshot
(JSON), then produces a combined findings report. Designed to run fully
offline against exported data - no OCI SDK, no credentials, no tenancy.
"""
import argparse
import csv
import json
import sys
from dataclasses import dataclass, field
from datetime import date

SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
ADMIN_PORTS = {22, 3389}
# Data-service ports: port -> (service, severity). Redis, MongoDB and Elasticsearch
# often run without authentication by default, so world exposure is rated CRITICAL.
DATA_PORTS = {
    3306: ("MySQL", "HIGH"),
    5432: ("PostgreSQL", "HIGH"),
    6379: ("Redis", "CRITICAL"),
    27017: ("MongoDB", "CRITICAL"),
    9200: ("Elasticsearch", "CRITICAL"),
}
API_KEY_AGE_WARN_DAYS = 90
MOM_SPIKE_PCT = 30.0
MOM_SPIKE_MIN_DELTA = 50.0
TOP_SPENDER_INFO = 500.0


@dataclass
class Finding:
    rule: str
    severity: str
    resource: str
    detail: str

    def as_dict(self):
        return {"rule": self.rule, "severity": self.severity,
                "resource": self.resource, "detail": self.detail}


@dataclass
class AuditResult:
    findings: list = field(default_factory=list)
    cost_by_service: dict = field(default_factory=dict)
    cost_by_compartment: dict = field(default_factory=dict)
    month_over_month: dict = field(default_factory=dict)

    def add(self, rule, severity, resource, detail):
        self.findings.append(Finding(rule, severity, resource, detail))

    def worst_severity(self):
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: SEVERITY_ORDER[f.severity]).severity


def load_cost_report(path):
    """Parse a cost report CSV: date,service,compartment,usage_amount,cost."""
    rows = []
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            rows.append({
                "date": date.fromisoformat(row["date"]),
                "service": row["service"],
                "compartment": row["compartment"],
                "usage_amount": float(row["usage_amount"]),
                "cost": float(row["cost"]),
            })
    if not rows:
        raise ValueError("cost report is empty")
    return rows


def _month_key(d):
    return f"{d.year:04d}-{d.month:02d}"


def analyze_cost(rows, budgets, result):
    by_service, by_compartment, by_month_service = {}, {}, {}
    by_month_compartment = {}
    for r in rows:
        by_service[r["service"]] = by_service.get(r["service"], 0.0) + r["cost"]
        by_compartment[r["compartment"]] = by_compartment.get(r["compartment"], 0.0) + r["cost"]
        key = (_month_key(r["date"]), r["service"])
        by_month_service[key] = by_month_service.get(key, 0.0) + r["cost"]
        ckey = (_month_key(r["date"]), r["compartment"])
        by_month_compartment[ckey] = by_month_compartment.get(ckey, 0.0) + r["cost"]

    months = sorted({m for m, _ in by_month_service})
    mom = {}
    if len(months) >= 2:
        prev, cur = months[-2], months[-1]
        services = {s for _, s in by_month_service}
        for s in services:
            p = by_month_service.get((prev, s), 0.0)
            c = by_month_service.get((cur, s), 0.0)
            if p > 0:
                pct = (c - p) / p * 100.0
                mom[s] = {"previous": round(p, 2), "current": round(c, 2), "change_pct": round(pct, 1)}
                if pct >= MOM_SPIKE_PCT and (c - p) >= MOM_SPIKE_MIN_DELTA:
                    result.add("cost_spike", "HIGH", f"service:{s}",
                               f"cost rose {pct:.0f}% month over month ({p:.2f} -> {c:.2f})")
    for svc, total in by_service.items():
        if total >= TOP_SPENDER_INFO:
            result.add("top_spender", "INFO", f"service:{svc}",
                       f"largest service cost in report window: {total:.2f}")
    budget_names = {b["name"] for b in budgets}
    latest_month = months[-1] if months else None
    for b in budgets:
        actual = by_month_compartment.get((latest_month, b.get("compartment", "")), 0.0)
        amount = float(b.get("amount", 0))
        if amount > 0 and actual > amount:
            result.add("budget_exceeded", "CRITICAL", f"budget:{b['name']}",
                       f"latest-month compartment cost {actual:.2f} exceeds monthly budget {amount:.2f}")
    result.cost_by_service = {k: round(v, 2) for k, v in sorted(by_service.items(), key=lambda kv: -kv[1])}
    result.cost_by_compartment = {k: round(v, 2) for k, v in sorted(by_compartment.items(), key=lambda kv: -kv[1])}
    result.month_over_month = mom
    return budget_names


def load_snapshot(path):
    with open(path, encoding="utf-8") as fh:
        snap = json.load(fh)
    for key in ("buckets", "security_lists", "iam_policies", "users", "budgets"):
        snap.setdefault(key, [])
    return snap


def _rule_ports(rule):
    """Ports covered by an ingress rule: `port`, or inclusive `port_range` [lo, hi]."""
    if "port_range" in rule:
        lo, hi = rule["port_range"]
        return range(int(lo), int(hi) + 1)
    return [rule["port"]] if "port" in rule else []


def _state_note(rule):
    if rule.get("stateless"):
        return "; stateless rule, return traffic needs its own egress rule and the rule is not connection-tracked"
    return "; stateful rule, return traffic is allowed automatically"


def audit_security(snap, result, today=None):
    today = today or date.today()
    for b in snap["buckets"]:
        if b.get("public_access"):
            result.add("public_bucket", "HIGH", f"bucket:{b['name']}",
                       "object storage bucket allows public access")
    for sl in snap["security_lists"]:
        for rule in sl.get("ingress", []):
            if rule.get("source") != "0.0.0.0/0":
                continue
            ports = set(_rule_ports(rule))
            for p in sorted(ports & ADMIN_PORTS):
                result.add("open_admin_port", "HIGH", f"security-list:{sl['name']}",
                           f"ingress from 0.0.0.0/0 to port {p}" + (_state_note(rule) if rule.get("stateless") else ""))
            for p in sorted(ports & set(DATA_PORTS)):
                svc, sev = DATA_PORTS[p]
                result.add("open_data_port", sev, f"security-list:{sl['name']}",
                           f"ingress from 0.0.0.0/0 to port {p} ({svc})" + _state_note(rule))
    for p in snap["iam_policies"]:
        for stmt in p.get("statements", []):
            low = stmt.lower()
            if "manage all-resources" in low and "in tenancy" in low and "admin" not in p.get("group", "").lower():
                result.add("broad_policy", "MEDIUM", f"policy:{p['name']}",
                           f"non-admin group '{p.get('group')}' can manage all-resources in tenancy")
    for u in snap["users"]:
        if not u.get("mfa_enabled"):
            result.add("user_without_mfa", "MEDIUM", f"user:{u['name']}",
                       "console user has no MFA enabled")
        for key in u.get("api_keys", []):
            age = (today - date.fromisoformat(key["created"])).days
            if age > API_KEY_AGE_WARN_DAYS:
                result.add("old_api_key", "LOW", f"user:{u['name']}",
                           f"API key is {age} days old (>{API_KEY_AGE_WARN_DAYS})")
    if not snap["budgets"]:
        result.add("no_budget", "MEDIUM", "tenancy",
                   "no budgets configured; spend has no guardrail")


def render_text(result):
    lines = ["=== OCI cost and security audit (offline export analysis) ===", ""]
    lines.append("Cost by service:")
    for svc, total in result.cost_by_service.items():
        lines.append(f"  {svc:<24} {total:>10.2f}")
    if result.month_over_month:
        lines.append("")
        lines.append("Month-over-month by service:")
        for svc, m in sorted(result.month_over_month.items()):
            lines.append(f"  {svc:<24} {m['previous']:>10.2f} -> {m['current']:>10.2f} ({m['change_pct']:+.1f}%)")
    lines.append("")
    lines.append(f"Findings ({len(result.findings)}):")
    for f in sorted(result.findings, key=lambda x: -SEVERITY_ORDER[x.severity]):
        lines.append(f"  [{f.severity:<8}] {f.rule:<18} {f.resource:<28} {f.detail}")
    if not result.findings:
        lines.append("  none")
    return "\n".join(lines)


def to_report(result):
    """Structured report shared by --json stdout and --output file."""
    counts = {}
    for f in result.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return {
        "summary": {
            "total_cost": round(sum(result.cost_by_service.values()), 2),
            "finding_count": len(result.findings),
            "findings_by_severity": counts,
            "worst_severity": result.worst_severity(),
        },
        "cost_by_service": result.cost_by_service,
        "cost_by_compartment": result.cost_by_compartment,
        "month_over_month": result.month_over_month,
        "findings": [f.as_dict() for f in sorted(
            result.findings, key=lambda x: -SEVERITY_ORDER[x.severity])],
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description="Offline OCI cost and security audit from exported data")
    ap.add_argument("--cost-report", required=True, help="CSV: date,service,compartment,usage_amount,cost")
    ap.add_argument("--snapshot", required=True, help="JSON tenancy configuration snapshot")
    ap.add_argument("--output", help="write JSON report here")
    ap.add_argument("--json", action="store_true", dest="json_out",
                    help="print the report as JSON on stdout instead of the text tables")
    ap.add_argument("--fail-on", choices=list(SEVERITY_ORDER), default=None,
                    help="exit 1 if any finding is at or above this severity (CI gate)")
    args = ap.parse_args(argv)

    result = AuditResult()
    rows = load_cost_report(args.cost_report)
    snap = load_snapshot(args.snapshot)
    analyze_cost(rows, snap["budgets"], result)
    audit_security(snap, result)

    if args.json_out:
        print(json.dumps(to_report(result), indent=2))
    else:
        print(render_text(result))
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(to_report(result), fh, indent=2)
    if args.fail_on and result.findings:
        worst = result.worst_severity()
        if SEVERITY_ORDER[worst] >= SEVERITY_ORDER[args.fail_on]:
            print(f"\nGate: worst finding {worst} >= --fail-on {args.fail_on}; failing.", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
