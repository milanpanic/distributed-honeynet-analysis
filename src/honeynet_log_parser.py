#!/usr/bin/env python3
"""
Original source code developed by the author for the research paper:

Title:
Design and Statistical Evaluation of a Distributed Honeynet Model
for Early Cyber Attack Detection

Author:
Milan Panić

Affiliation:
Pan-European University "APEIRON",
Faculty of Information Technology,
Banja Luka, Bosnia and Herzegovina

Purpose:
This script is part of the original supporting code for the laboratory
implementation and empirical evaluation of the distributed honeynet model.
It is used for parsing, normalization, correlation and/or statistical
processing of Cowrie and DDoSPot honeynet data used in the paper.
- Reads Cowrie JSON/JSONL log files.
- Reads DDoSPot JSON/JSONL or simple text log files.
- Normalizes heterogeneous records into one forensic schema.
- Adds correlation_id and a simple conceptual risk_score.
- Writes normalized_events.csv, normalized_events.jsonl and parser_summary.txt.

Research context:
The code was developed for a controlled VMware-based laboratory environment
consisting of a gateway/firewall, Cowrie SSH/Telnet sensor, DDoSPot UDP sensor,
analysis host and isolated sensor subnet.

Copyright:
Copyright (c) 2026 Milan Panić. All rights reserved.

Note:
This code represents the author's original research-supporting implementation.
It is provided as supplementary material for verification, reproducibility
and academic review of the results presented in the paper.

Expected use in the paper workflow:
Raw Cowrie/DDoSPot logs  ->  this parser  ->  normalized CSV/JSON  ->  statistics/reporting scripts.

This parser is intentionally defensive because Cowrie and DDoSPot log formats can vary
by version and local configuration. It preserves the original raw line in raw_message.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


NORMALIZED_FIELDS = [
    "event_id",
    "timestamp",
    "sensor_id",
    "service",
    "protocol",
    "source_ip",
    "destination_port",
    "session_id",
    "username",
    "password",
    "command",
    "payload_hash",
    "raw_message",
    "correlation_id",
    "risk_score",
]


IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PORT_RE = re.compile(r"(?:port|dport|dst_port|destination_port)[=: ]+(\d{1,5})", re.I)
SERVICE_RE = re.compile(r"\b(dns|ntp|ssdp|chargen|udp|ssh|telnet)\b", re.I)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Parse and normalize Cowrie and DDoSPot logs into a common forensic schema."
    )
    parser.add_argument("--cowrie-dir", type=Path, default=None,
                        help="Directory containing Cowrie JSON/JSONL/log files.")
    parser.add_argument("--ddospot-dir", type=Path, default=None,
                        help="Directory containing DDoSPot JSON/JSONL/text log files.")
    parser.add_argument("--output-dir", type=Path, default=Path("normalized_output"),
                        help="Directory where normalized outputs will be written.")
    parser.add_argument("--time-window-min", type=int, default=10,
                        help="Correlation time window in minutes. Default: 10.")
    return parser.parse_args()


def iter_log_files(directory: Optional[Path]) -> Iterable[Path]:
    if directory is None:
        return []
    if not directory.exists():
        raise FileNotFoundError(f"Directory not found: {directory}")
    patterns = ["*.json", "*.jsonl", "*.log", "*.txt"]
    files: List[Path] = []
    for pattern in patterns:
        files.extend(directory.rglob(pattern))
    return sorted(set(files))


def safe_json_loads(line: str) -> Optional[Dict[str, Any]]:
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError:
        return None
    return None


def normalize_timestamp(value: Any) -> str:
    """
    Return ISO-8601 timestamp when possible. If parsing fails, return the original value.
    Cowrie usually stores ISO-like timestamp strings.
    """
    if value is None:
        return ""
    text = str(value).strip()
    if not text:
        return ""

    # Already ISO-like
    if "T" in text and ("+" in text or "Z" in text or "." in text):
        return text.replace("Z", "+00:00")

    # Common log timestamp variants
    candidates = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%b %d %H:%M:%S",
    ]
    for fmt in candidates:
        try:
            dt = datetime.strptime(text[:19], fmt)
            if fmt == "%b %d %H:%M:%S":
                dt = dt.replace(year=datetime.now().year)
            return dt.replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            continue

    return text


def time_bucket(timestamp: str, window_min: int) -> str:
    """
    Convert timestamp into a coarse bucket for correlation.
    If timestamp cannot be parsed, return an empty bucket.
    """
    if not timestamp:
        return ""
    try:
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        minute = (dt.minute // window_min) * window_min
        bucket = dt.replace(minute=minute, second=0, microsecond=0)
        return bucket.isoformat()
    except Exception:
        return ""


def make_correlation_id(source_ip: str, session_id: str, service: str, timestamp: str, window_min: int) -> str:
    bucket = time_bucket(timestamp, window_min)
    base = "|".join([source_ip or "unknown_src", session_id or "no_session", service or "unknown_service", bucket])
    return hashlib.sha1(base.encode("utf-8", errors="replace")).hexdigest()[:16]


def sha256_text(value: str) -> str:
    if not value:
        return ""
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def extract_first_ip(text: str) -> str:
    match = IP_RE.search(text or "")
    return match.group(0) if match else ""


def extract_port(text: str) -> str:
    match = PORT_RE.search(text or "")
    return match.group(1) if match else ""


def infer_service_from_port(port: str) -> str:
    return {
        "22": "ssh",
        "23": "telnet",
        "53": "dns",
        "123": "ntp",
        "1900": "ssdp",
        "19": "chargen",
    }.get(str(port), "")


def infer_protocol(service: str, destination_port: str, event_id: str = "") -> str:
    service_l = (service or "").lower()
    event_l = (event_id or "").lower()
    port = str(destination_port or "")
    if service_l in {"dns", "ntp", "ssdp", "chargen"} or port in {"53", "123", "1900", "19"}:
        return "UDP"
    if service_l in {"ssh", "telnet"} or port in {"22", "23"}:
        return "TCP"
    if "udp" in event_l:
        return "UDP"
    return ""


def risk_score(record: Dict[str, str]) -> int:
    """
    Simple conceptual risk score from 0 to 100.
    This implements the logic described in the paper:
    credential intensity, payload indicators, service spread/context and temporal/session indicators.
    
    """
    score = 0

    event_id = (record.get("event_id") or "").lower()
    username = record.get("username") or ""
    password = record.get("password") or ""
    command = (record.get("command") or "").lower()
    service = (record.get("service") or "").lower()
    raw = (record.get("raw_message") or "").lower()

    # C: credential abuse
    if username or password or "login" in event_id or "auth" in event_id:
        score += 25

    # P: payload / malware / download indicators
    payload_terms = ["wget", "curl", "tftp", "ftp", "download", "chmod", "sh ", ".sh", "malware", "payload"]
    if any(term in command or term in raw for term in payload_terms):
        score += 20
        if command:
            record["payload_hash"] = sha256_text(command)

    # S: service spread / non-SSH service evidence
    if service in {"dns", "ntp", "ssdp", "chargen"}:
        score += 20
    elif service in {"ssh", "telnet"}:
        score += 10

    # B: context, suspicious tooling or known noisy behavior
    context_terms = ["scanner", "nmap", "masscan", "mirai", "bot", "exploit", "invalid", "failed"]
    if any(term in raw for term in context_terms):
        score += 15

    # T: temporal/session activity indicator
    if record.get("session_id") or "session" in event_id or "connection" in event_id:
        score += 10

    return max(0, min(100, score))


def normalize_cowrie(obj: Dict[str, Any], raw_line: str, window_min: int) -> Dict[str, str]:
    event_id = str(obj.get("eventid") or obj.get("event_id") or "")
    timestamp = normalize_timestamp(obj.get("timestamp") or obj.get("time"))
    source_ip = str(obj.get("src_ip") or obj.get("source_ip") or obj.get("remote_host") or "")
    destination_port = str(obj.get("dst_port") or obj.get("destination_port") or obj.get("port") or "")
    service = str(obj.get("service") or infer_service_from_port(destination_port) or "ssh")
    command = str(obj.get("input") or obj.get("command") or "")
    session_id = str(obj.get("session") or obj.get("session_id") or "")

    record = {
        "event_id": event_id,
        "timestamp": timestamp,
        "sensor_id": "cowrie",
        "service": service,
        "protocol": infer_protocol(service, destination_port, event_id),
        "source_ip": source_ip,
        "destination_port": destination_port,
        "session_id": session_id,
        "username": str(obj.get("username") or ""),
        "password": str(obj.get("password") or ""),
        "command": command,
        "payload_hash": sha256_text(command) if command else "",
        "raw_message": raw_line.strip(),
        "correlation_id": "",
        "risk_score": "0",
    }
    record["correlation_id"] = make_correlation_id(source_ip, session_id, service, timestamp, window_min)
    record["risk_score"] = str(risk_score(record))
    return record


def normalize_ddospot_json(obj: Dict[str, Any], raw_line: str, window_min: int) -> Dict[str, str]:
    event_id = str(obj.get("eventid") or obj.get("event_id") or obj.get("type") or "ddospot.event")
    timestamp = normalize_timestamp(obj.get("timestamp") or obj.get("time") or obj.get("ts"))
    source_ip = str(obj.get("src_ip") or obj.get("source_ip") or obj.get("remote_ip") or obj.get("client_ip") or "")
    destination_port = str(obj.get("dst_port") or obj.get("destination_port") or obj.get("port") or "")
    service = str(obj.get("service") or obj.get("protocol_name") or infer_service_from_port(destination_port) or "udp").lower()
    session_id = str(obj.get("session") or obj.get("session_id") or "")

    record = {
        "event_id": event_id,
        "timestamp": timestamp,
        "sensor_id": "ddospot",
        "service": service,
        "protocol": infer_protocol(service, destination_port, event_id) or "UDP",
        "source_ip": source_ip,
        "destination_port": destination_port,
        "session_id": session_id,
        "username": "",
        "password": "",
        "command": "",
        "payload_hash": "",
        "raw_message": raw_line.strip(),
        "correlation_id": "",
        "risk_score": "0",
    }
    record["correlation_id"] = make_correlation_id(source_ip, session_id, service, timestamp, window_min)
    record["risk_score"] = str(risk_score(record))
    return record


def normalize_ddospot_text(line: str, window_min: int) -> Dict[str, str]:
    text = line.strip()
    source_ip = extract_first_ip(text)
    destination_port = extract_port(text)

    service_match = SERVICE_RE.search(text)
    service = service_match.group(1).lower() if service_match else infer_service_from_port(destination_port) or "udp"

    # Try to capture a timestamp at the beginning of the line.
    timestamp = ""
    ts_match = re.match(r"^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})", text)
    if ts_match:
        timestamp = normalize_timestamp(ts_match.group(1))

    record = {
        "event_id": "ddospot.text_event",
        "timestamp": timestamp,
        "sensor_id": "ddospot",
        "service": service,
        "protocol": infer_protocol(service, destination_port, "ddospot.text_event") or "UDP",
        "source_ip": source_ip,
        "destination_port": destination_port,
        "session_id": "",
        "username": "",
        "password": "",
        "command": "",
        "payload_hash": "",
        "raw_message": text,
        "correlation_id": "",
        "risk_score": "0",
    }
    record["correlation_id"] = make_correlation_id(source_ip, "", service, timestamp, window_min)
    record["risk_score"] = str(risk_score(record))
    return record


def parse_cowrie_file(path: Path, window_min: int) -> Iterable[Dict[str, str]]:
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            obj = safe_json_loads(line)
            if obj is None:
                continue
            yield normalize_cowrie(obj, line, window_min)


def parse_ddospot_file(path: Path, window_min: int) -> Iterable[Dict[str, str]]:
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if not line.strip():
                continue
            obj = safe_json_loads(line)
            if obj is not None:
                yield normalize_ddospot_json(obj, line, window_min)
            else:
                yield normalize_ddospot_text(line, window_min)


def write_outputs(records: List[Dict[str, str]], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    csv_path = output_dir / "normalized_events.csv"
    jsonl_path = output_dir / "normalized_events.jsonl"
    summary_path = output_dir / "parser_summary.txt"

    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=NORMALIZED_FIELDS)
        writer.writeheader()
        for rec in records:
            writer.writerow({field: rec.get(field, "") for field in NORMALIZED_FIELDS})

    with jsonl_path.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps({field: rec.get(field, "") for field in NORMALIZED_FIELDS}, ensure_ascii=False) + "\n")

    by_sensor = Counter(rec.get("sensor_id", "") for rec in records)
    by_service = Counter(rec.get("service", "") for rec in records)
    unique_sources = {rec.get("source_ip") for rec in records if rec.get("source_ip")}
    high_risk = sum(1 for rec in records if int(rec.get("risk_score") or 0) >= 71)
    medium_risk = sum(1 for rec in records if 31 <= int(rec.get("risk_score") or 0) <= 70)
    low_risk = sum(1 for rec in records if int(rec.get("risk_score") or 0) <= 30)

    summary_lines = [
        "Honeynet parser summary",
        "=" * 40,
        f"Total normalized events: {len(records)}",
        f"Unique source IP addresses: {len(unique_sources)}",
        "",
        "Events by sensor:",
        *[f"- {sensor}: {count}" for sensor, count in sorted(by_sensor.items())],
        "",
        "Events by service:",
        *[f"- {service}: {count}" for service, count in sorted(by_service.items())],
        "",
        "Risk-score distribution:",
        f"- Low risk 0-30: {low_risk}",
        f"- Medium risk 31-70: {medium_risk}",
        f"- High risk 71-100: {high_risk}",
        "",
        f"CSV output: {csv_path}",
        f"JSONL output: {jsonl_path}",
    ]
    summary_path.write_text("\n".join(summary_lines), encoding="utf-8")


def main() -> None:
    args = parse_args()

    records: List[Dict[str, str]] = []

    for path in iter_log_files(args.cowrie_dir):
        records.extend(parse_cowrie_file(path, args.time_window_min))

    for path in iter_log_files(args.ddospot_dir):
        records.extend(parse_ddospot_file(path, args.time_window_min))

    # Deduplicate exact normalized raw messages while preserving order.
    seen = set()
    deduped: List[Dict[str, str]] = []
    for rec in records:
        key = (rec.get("sensor_id"), rec.get("raw_message"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(rec)

    write_outputs(deduped, args.output_dir)
    print(f"Normalized events written to: {args.output_dir / 'normalized_events.csv'}")
    print(f"JSONL output written to: {args.output_dir / 'normalized_events.jsonl'}")
    print(f"Summary written to: {args.output_dir / 'parser_summary.txt'}")


if __name__ == "__main__":
    main()
