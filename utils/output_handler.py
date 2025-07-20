import json
import csv
import os

def handle_output(findings, output_format=None, output_file=None):
    if not findings:
        print("No findings.")
        return

    if output_format == "json":
        _write_json(findings, output_file)
    elif output_format == "csv":
        _write_csv(findings, output_file)
    else:
        _print_cli(findings)

def _print_cli(findings):
    print("Findings:")
    for item in findings:
        print("-", item)

def _write_json(findings, path):
    path = path or "findings.json"
    with open(path, "w") as f:
        json.dump(findings, f, indent=2)
    print(f"[INFO] Findings written to {path}")

def _write_csv(findings, path):
    path = path or "findings.csv"
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Issue"])
        for item in findings:
            writer.writerow([item])
    print(f"[INFO] Findings written to {path}")
