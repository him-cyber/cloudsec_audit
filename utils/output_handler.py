import json
import csv
import os
from datetime import datetime

def handle_output(audit_type, findings, profile=None, output_format=None, output_file=None):
    if not findings:
        print("[INFO] No findings.")
        return

    reports_dir = os.path.join(os.getcwd(), "reports")
    os.makedirs(reports_dir, exist_ok=True)

    if output_file:
        path = os.path.join(reports_dir, os.path.basename(output_file))
    else:
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        profile_str = profile or "default"
        extension = "csv" if output_format == "csv" else "json"
        filename = f"{audit_type}_{profile_str}_{timestamp}.{extension}"
        path = os.path.join(reports_dir, filename)

    if output_format == "csv":
        _write_csv(findings, path)
    elif output_format == "json":
        _write_json(findings, path)
    else:
        _print_cli(findings)

def _print_cli(findings):
    print("Findings:")
    for item in findings:
        print("-", item)

def _write_json(findings, path):
    with open(path, "w") as f:
        json.dump(findings, f, indent=2)
    print(f"[INFO] Findings written to {path}")

def _write_csv(findings, path):
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Issue"])
        for item in findings:
            writer.writerow([item])
    print(f"[INFO] Findings written to {path}")
