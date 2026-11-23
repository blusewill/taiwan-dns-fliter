#!/usr/bin/env python3

import csv
import io
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


DATASETS = {
    "160055": "https://data.gov.tw/api/v2/rest/dataset/160055",
    "176455": "https://data.gov.tw/api/v2/rest/dataset/176455",
}

OUTPUT = Path("filters/165.txt")

USER_AGENT = (
    "Mozilla/5.0 "
    "(compatible; Taiwan-165-DNS-Blocklist/1.0; "
    "+https://github.com/)"
)

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}$",
    re.IGNORECASE,
)


def fetch(url: str) -> bytes:
    """下載 URL 內容。"""
    request = Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "*/*",
        },
    )

    with urlopen(request, timeout=60) as response:
        return response.read()


def get_dataset_metadata(dataset_id: str) -> dict:
    """取得 data.gov.tw dataset metadata。"""
    metadata_url = DATASETS[dataset_id]

    print(f"[INFO] Fetching metadata: dataset {dataset_id}")
    data = fetch(metadata_url)

    try:
        return json.loads(data.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Dataset {dataset_id} metadata 不是有效 JSON"
        ) from exc


def normalize_key(value: str) -> str:
    """欄位名稱標準化。"""
    return (
        value.strip()
        .replace("\ufeff", "")
        .replace(" ", "")
        .replace("_", "")
        .lower()
    )


def find_csv_resources(metadata: dict) -> list[dict]:
    """
    從 dataset metadata 找出 CSV 資源。

    主要依據 distribution/resourceDownloadUrl，
    同時容忍 API metadata 結構稍有差異。
    """

    resources = []

    def walk(obj):
        if isinstance(obj, dict):
            # 找 distribution/resource 類型的物件
            has_url = any(
                normalize_key(k) in {
                    "resourcedownloadurl",
                    "downloadurl",
                }
                for k in obj.keys()
            )

            if has_url:
                resources.append(obj)

            for value in obj.values():
                walk(value)

        elif isinstance(obj, list):
            for item in obj:
                walk(item)

    walk(metadata)

    csv_resources = []

    for resource in resources:
        url = None
        fmt = None

        for key, value in resource.items():
            key_norm = normalize_key(key)

            if key_norm in {
                "resourcedownloadurl",
                "downloadurl",
            }:
                if isinstance(value, str):
                    url = value.strip()

            elif key_norm in {
                "format",
                "fileformat",
                "resourceformat",
            }:
                if isinstance(value, str):
                    fmt = value.strip().lower()

        if not url:
            continue

        # 優先相信 metadata 的 format。
        if fmt:
            is_csv = (
                fmt == "csv"
                or "csv" in fmt
            )
        else:
            # metadata 沒提供 format 時才從 URL 判斷
            path = urlsplit(url).path.lower()
            is_csv = path.endswith(".csv")

        if is_csv:
            csv_resources.append({
                "url": url,
                "format": fmt,
                "raw": resource,
            })

    return csv_resources


def get_csv_url(dataset_id: str) -> str:
    """從最新 metadata 找 CSV 下載網址。"""
    metadata = get_dataset_metadata(dataset_id)

    resources = find_csv_resources(metadata)

    if not resources:
        raise RuntimeError(
            f"Dataset {dataset_id} 找不到 CSV resourceDownloadURL"
        )

    # 通常資料集只會有一個主要 CSV。
    # 如果未來出現多個 CSV，優先使用第一個。
    resource = resources[0]

    csv_url = resource["url"]

    print(f"[INFO] Dataset {dataset_id} CSV:")
    print(f"       {csv_url}")

    return csv_url


def download_csv(dataset_id: str) -> str:
    """取得指定資料集最新 CSV。"""
    csv_url = get_csv_url(dataset_id)

    print(f"[INFO] Downloading dataset {dataset_id}...")

    data = fetch(csv_url)

    # data.gov.tw CSV 通常使用 UTF-8，
    # utf-8-sig 可以同時處理 BOM。
    return data.decode("utf-8-sig", errors="replace")


def normalize_domain(value: str) -> str | None:
    """將 URL / domain 正規化成 DNS hostname。"""

    if not value:
        return None

    value = value.strip()
    value = value.strip('"').strip("'")

    if not value:
        return None

    # URL → hostname
    if "://" in value:
        try:
            hostname = urlsplit(value).hostname
        except ValueError:
            return None

        if not hostname:
            return None

        value = hostname

    # 如果資料是：
    # example.com/path
    # example.com:443
    value = value.split("/")[0]
    value = value.split(":")[0]

    value = value.strip().strip(".").lower()

    if not value:
        return None

    # 排除 IP
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", value):
        return None

    # IDN → punycode
    try:
        value = value.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None

    if not DOMAIN_RE.fullmatch(value):
        return None

    return value


def find_column(fieldnames, candidates):
    """尋找 CSV 欄位名稱。"""

    if not fieldnames:
        return None

    normalized = {
        normalize_key(field): field
        for field in fieldnames
    }

    for candidate in candidates:
        candidate_norm = normalize_key(candidate)

        if candidate_norm in normalized:
            return normalized[candidate_norm]

    # 模糊比對
    for field in fieldnames:
        field_norm = normalize_key(field)

        for candidate in candidates:
            candidate_norm = normalize_key(candidate)

            if candidate_norm in field_norm:
                return field

    return None


def extract_domains_160055(csv_text: str) -> set[str]:
    """
    Dataset 160055
    「假投資(博弈)網站」

    主要欄位：
    網站名稱、網址、件數、統計起始日期、統計結束日期
    """

    reader = csv.DictReader(io.StringIO(csv_text))

    url_column = find_column(
        reader.fieldnames,
        ["網址", "URL", "url"],
    )

    if not url_column:
        raise RuntimeError(
            "Dataset 160055 找不到網址欄位。\n"
            f"目前欄位：{reader.fieldnames}"
        )

    domains = set()

    for row in reader:
        domain = normalize_domain(row.get(url_column, ""))

        if domain:
            domains.add(domain)

    return domains


def extract_domains_176455(csv_text: str) -> set[str]:
    """
    Dataset 176455
    「遭停止解析涉詐網站」

    主要欄位：
    民國年月、網域、網站性質、法律依據、聲請單位
    """

    reader = csv.DictReader(io.StringIO(csv_text))

    domain_column = find_column(
        reader.fieldnames,
        ["網域", "Domain", "domain"],
    )

    if not domain_column:
        raise RuntimeError(
            "Dataset 176455 找不到網域欄位。\n"
            f"目前欄位：{reader.fieldnames}"
        )

    domains = set()

    for row in reader:
        domain = normalize_domain(row.get(domain_column, ""))

        if domain:
            domains.add(domain)

    return domains


def generate_blocklist(domains: set[str]):
    """產生 AdGuard DNS filter。"""

    if not domains:
        raise RuntimeError(
            "最後沒有任何有效網域，為避免覆蓋既有清單而停止。"
        )

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        "! Title: Taiwan 165 Scam Page Blocklist",
        "! Source: data.gov.tw dataset 160055 + 176455",
        "! Generated automatically by GitHub Actions",
        "! Format: AdGuard DNS filter",
        f"! Domains: {len(domains)}",
        "",
    ]

    for domain in sorted(domains):
        lines.append(f"||{domain}^")

    OUTPUT.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )

    print(f"[INFO] Generated: {OUTPUT}")
    print(f"[INFO] Total domains: {len(domains)}")


def main():
    try:
        print("=" * 60)
        print("Taiwan 165 Scam Page Blocklist")
        print("=" * 60)

        all_domains = set()

        # 160055
        csv_160055 = download_csv("160055")
        domains_160055 = extract_domains_160055(csv_160055)

        print(
            f"[INFO] Dataset 160055 domains: "
            f"{len(domains_160055)}"
        )

        all_domains.update(domains_160055)

        # 176455
        csv_176455 = download_csv("176455")
        domains_176455 = extract_domains_176455(csv_176455)

        print(
            f"[INFO] Dataset 176455 domains: "
            f"{len(domains_176455)}"
        )

        all_domains.update(domains_176455)

        print(
            f"[INFO] Combined unique domains: "
            f"{len(all_domains)}"
        )

        generate_blocklist(all_domains)

        print("=" * 60)
        print("Update completed successfully")
        print("=" * 60)

    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
