
#!/usr/bin/env python3

import os
import re
import ipaddress
from pathlib import Path
from urllib.parse import urlsplit

FILTER_DIR = Path("filters")
OUTPUT = FILTER_DIR / "user-report.txt"

PLACEHOLDER = "請把我刪掉在開始丟！"

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

    # 支援一般網址
    if "://" in value:
        try:
            value = urlsplit(value).hostname or ""
        except ValueError:
            return None

    # 支援 AdGuard 格式
    if value.startswith("||"):
        value = value[2:].split("^")[0]

    value = value.strip().strip(".").lower()

    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None

    if not value or not DOMAIN_RE.fullmatch(value):
        return None

    try:
        ipaddress.ip_address(value)
        return None
    except ValueError:
        pass

    return value


def parse_issue(body):
    # 只接受一個 Markdown 程式碼區塊
    blocks = re.findall(
        r"```(?:[^\n`]*)\n(.*?)```",
        body,
        re.DOTALL,
    )

    if len(blocks) != 1:
        raise ValueError(
            "投稿必須包含且只能包含一個三個反引號的程式碼區塊。"
        )

    content = blocks[0].strip()

    if not content or PLACEHOLDER in content:
        raise ValueError(
            "請先刪除範例文字，再於程式碼區塊中填入網域。"
        )

    domains = set()

    for line_number, line in enumerate(content.splitlines(), 1):
        line = line.strip()

        if not line:
            continue

        domain = normalize_domain(line)

        if not domain:
            raise ValueError(
                f"第 {line_number} 行不是有效的網域：{line}"
            )

        domains.add(domain)

    if not domains:
        raise ValueError("沒有找到有效網域。")

    return domains


def extract_existing_domains():
    existing = set()

    for path in FILTER_DIR.rglob("*"):
        if not path.is_file() or path == OUTPUT:
            continue

        try:
            content = path.read_text(
                encoding="utf-8-sig",
                errors="replace",
            )
        except OSError:
            continue

        for line in content.splitlines():
            line = line.strip()

            if not line or line.startswith(("!", "#", ";")):
                continue

            # AdGuard DNS filter
            if line.startswith("||"):
                domain = normalize_domain(line)
                if domain:
                    existing.add(domain)
                continue

            # hosts 格式：0.0.0.0 domain.com
            parts = line.split()

            if len(parts) >= 2:
                try:
                    ipaddress.ip_address(parts[0])
                    for item in parts[1:]:
                        domain = normalize_domain(item)
                        if domain:
                            existing.add(domain)
                    continue
                except ValueError:
                    pass

            # 純網域或網址格式
            domain = normalize_domain(line)

            if domain:
                existing.add(domain)

    return existing


def set_output(key, value):
    with open(os.environ["GITHUB_OUTPUT"], "a") as f:
        f.write(f"{key}={value}\n")


def main():
    title = os.environ.get("ISSUE_TITLE", "")
    body = os.environ.get("ISSUE_BODY", "")

    try:
        if not title.startswith("[Blocklist]"):
            raise ValueError(
                "Issue 標題必須以 [Blocklist] 開頭。"
            )

        submitted = parse_issue(body)

        existing = extract_existing_domains()

        new_domains = sorted(submitted - existing)
        duplicates = sorted(submitted & existing)

        if not new_domains:
            set_output("status", "duplicate")
            set_output(
                "duplicates",
                ",".join(duplicates),
            )
            print("所有投稿網域都已經存在。")
            return

        OUTPUT.parent.mkdir(parents=True, exist_ok=True)

        current = set()

        if OUTPUT.exists():
            for line in OUTPUT.read_text(
                encoding="utf-8-sig"
            ).splitlines():
                domain = normalize_domain(line)
                if domain:
                    current.add(domain)

        combined = sorted(current | set(new_domains))

        OUTPUT.write_text(
            "\n".join(combined) + "\n",
            encoding="utf-8",
        )

        set_output("status", "success")
        set_output("new_count", str(len(new_domains)))
        set_output("duplicate_count", str(len(duplicates)))
        set_output("new_domains", ",".join(new_domains))
        set_output("duplicates", ",".join(duplicates))

        print(f"New domains: {len(new_domains)}")
        print(f"Duplicates: {len(duplicates)}")

    except ValueError as exc:
        set_output("status", "invalid")
        set_output("error", str(exc))
        print(f"Invalid submission: {exc}")


if __name__ == "__main__":
    main()
