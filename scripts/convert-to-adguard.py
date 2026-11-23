#!/usr/bin/env python3

import ipaddress
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

FILTER_DIR = Path("filters")
OUTPUT = Path("filter.txt")

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}$",
    re.IGNORECASE,
)


def normalize_domain(value):
    value = value.strip()

    if not value:
        return None

    # 忽略註解
    if value.startswith(("!", "#", ";")):
        return None

    # AdGuard DNS 格式：||example.com^
    if value.startswith("||"):
        value = value[2:].split("^")[0]

    # 忽略例外規則
    if value.startswith("@@"):
        return None

    # URL 格式
    if "://" in value:
        try:
            value = urlsplit(value).hostname or ""
        except ValueError:
            return None

    # Hosts 格式：0.0.0.0 example.com
    parts = value.split()

    if len(parts) >= 2:
        try:
            ipaddress.ip_address(parts[0])
            value = parts[1]
        except ValueError:
            pass

    # 移除路徑與連接埠
    value = value.split("/")[0]
    value = value.split(":")[0]
    value = value.strip().strip(".").lower()

    if not value:
        return None

    # IDN 轉換成 Punycode
    try:
        value = value.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None

    # 排除 IP
    try:
        ipaddress.ip_address(value)
        return None
    except ValueError:
        pass

    if not DOMAIN_RE.fullmatch(value):
        return None

    return value


def collect_domains():
    domains = set()
    scanned_files = 0

    if not FILTER_DIR.exists():
        raise RuntimeError("找不到 filters/ 目錄")

    for path in sorted(FILTER_DIR.rglob("*")):
        if not path.is_file():
            continue

        scanned_files += 1

        try:
            content = path.read_text(
                encoding="utf-8-sig",
                errors="replace",
            )
        except OSError as exc:
            raise RuntimeError(
                f"無法讀取檔案 {path}: {exc}"
            ) from exc

        for line in content.splitlines():
            domain = normalize_domain(line)

            if domain:
                domains.add(domain)

        print(f"[INFO] Scanned: {path}")

    print(f"[INFO] Files scanned: {scanned_files}")
    print(f"[INFO] Unique domains: {len(domains)}")

    if not domains:
        raise RuntimeError(
            "沒有找到有效網域，停止產生 filter.txt"
        )

    return domains


def generate_filter(domains):
    lines = [
        "! Title: My DNS Blocklist",
        "! Description: Combined DNS Blocklist",
        "! Format: AdGuard DNS Filtering",
        "! Source: filters/",
        f"! Total domains: {len(domains)}",
        "",
    ]

    for domain in sorted(domains):
        lines.append(f"||{domain}^")

    content = "\n".join(lines) + "\n"

    # 先寫入暫存檔，成功後才取代正式檔案
    temporary = OUTPUT.with_suffix(".txt.tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.replace(OUTPUT)

    print(f"[INFO] Generated: {OUTPUT}")
    print(f"[INFO] Total rules: {len(domains)}")


def main():
    try:
        print("=" * 50)
        print("Building Combined AdGuard DNS Filter")
        print("=" * 50)

        domains = collect_domains()
        generate_filter(domains)

        print("[SUCCESS] Filter build completed.")

    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
