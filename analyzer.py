"""Compare normalized inventory snapshots and identify security field changes."""

FIELDS = {"public": True, "encrypted": False, "logging_enabled": False, "mfa_enabled": False}

def analyze(data):
    def index(items):
        out = {}
        for item in items:
            if item["id"] in out:
                raise ValueError("Duplicate resource ID")
            out[item["id"]] = item
        return out
    before, after = index(data["before"]), index(data["after"])
    out = []
    for rid in sorted(before.keys() | after.keys()):
        if rid not in before or rid not in after:
            out.append(finding(rid, "INFO", "RESOURCE_ADDED" if rid not in before else "RESOURCE_REMOVED", "Resource inventory membership changed.", "Verify approved inventory change.", {"before": before.get(rid), "after": after.get(rid)}))
            continue
        for field, unsafe in FIELDS.items():
            old, new = before[rid].get(field), after[rid].get(field)
            if old == new:
                continue
            severity = "UNKNOWN" if old is None or new is None else ("HIGH" if new == unsafe else "INFO")
            out.append(finding(rid, severity, "SECURITY_DRIFT", f"{field} changed.", "Validate change authorization and required security controls.", {"field": field, "before": old, "after": new}))
    return out

import argparse
import json
import sys
from pathlib import Path

def finding(resource, severity, check, detail, remediation, evidence):
    return dict(resource=resource, severity=severity, check=check, detail=detail, remediation=remediation, evidence=evidence)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("input", type=Path)
    p.add_argument("--output", type=Path)
    p.add_argument("--fail-on-high", action="store_true")
    args = p.parse_args()
    try:
        data = json.loads(args.input.read_text(encoding="utf-8-sig"))
        if not isinstance(data, dict):
            raise ValueError("Expected JSON object")
        results = analyze(data)
        text = json.dumps({"results": results, "count": len(results), "scope": __doc__}, indent=2)
        if args.output:
            args.output.write_text(text + "\n", encoding="utf-8")
        else:
            print(text)
        return int(args.fail_on_high and any(r["severity"] == "HIGH" for r in results))
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as e:
        print(f"Input/report error: {e}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())

