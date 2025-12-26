# tracker_analysis.py
import zipfile
import re
from urllib.parse import urlparse
from typing import Dict, Set
import csv
import os

# URL regex (bytes)
URL_PATTERN = re.compile(rb"https?://[^\s\"'<>]+")
HERE = os.path.dirname(__file__)
TRACKERS_CSV = os.path.join(HERE, "trackers.csv")


def load_tracker_list():
    trackers = []
    try:
        with open(TRACKERS_CSV, newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                dom = row.get("domain", "").strip().lower()
                cat = row.get("category", "tracker").strip().lower()
                if dom:
                    trackers.append((dom, cat))
    except Exception:
        # fallback small built-in list if CSV missing
        trackers = [
            ("doubleclick.net", "ads"),
            ("google-analytics.com", "analytics"),
            ("googlesyndication.com", "ads"),
            ("firebaseio.com", "backend"),
            ("facebook.com", "social"),
        ]
    return trackers


TRACKER_PATTERNS = load_tracker_list()


def _clean_domain(url: str) -> str:
    try:
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        if ":" in host:
            host = host.split(":", 1)[0]
        if host.startswith("www."):
            host = host[4:]
        return host
    except Exception:
        return ""


def extract_domains_from_apk(apk_path: str, max_file_size: int = 2_000_000) -> Set[str]:
    domains: Set[str] = set()
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                name = info.filename.lower()

                # skip some heavy binary types
                if name.endswith((
                    ".so", ".png", ".jpg", ".jpeg", ".webp",
                    ".gif", ".mp3", ".mp4", ".ogg", ".wav",
                    ".ttf", ".otf", ".ico", ".pdf"
                )):
                    continue

                # skip huge files (performance)
                if info.file_size > max_file_size:
                    continue

                try:
                    data = zf.read(info)
                except Exception:
                    continue

                # search for urls in raw bytes (works for text and many binary blobs)
                for match in URL_PATTERN.findall(data):
                    try:
                        url = match.decode("utf-8", errors="ignore")
                    except Exception:
                        continue
                    domain = _clean_domain(url)
                    if domain:
                        domains.add(domain)

    except Exception:
        return set()

    return domains


def classify_domains(domains: Set[str]) -> Dict:
    tracker_domains: Dict[str, str] = {}
    category_counts: Dict[str, int] = {}

    for dom in domains:
        matched_category = None
        for pattern, category in TRACKER_PATTERNS:
            # match pattern as suffix or substring (covers subdomains)
            if pattern in dom:
                matched_category = category
                break

        if matched_category:
            tracker_domains[dom] = matched_category
            category_counts[matched_category] = category_counts.get(matched_category, 0) + 1

    num_trackers = len(tracker_domains)
    num_domains = len(domains)

    if num_trackers == 0:
        risk_level = "LOW"
    elif num_trackers <= 3:
        risk_level = "MEDIUM"
    elif num_trackers <= 10:
        risk_level = "MEDIUM"
    else:
        risk_level = "HIGH"

    return {
        "all_domains": sorted(domains),
        "tracker_domains": tracker_domains,
        "num_domains": num_domains,
        "num_trackers": num_trackers,
        "category_counts": category_counts,
        "risk_level": risk_level,
    }


def analyze_trackers(apk_path: str) -> Dict:
    domains = extract_domains_from_apk(apk_path)
    summary = classify_domains(domains)
    return summary
