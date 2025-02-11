"""
cli.py — Interactive command-line interface for the Phishing Detector.
Uses only the standard library + optional `rich` for pretty output.
Falls back gracefully if `rich` is not installed.
"""

import sys
import json
import textwrap
from pathlib import Path

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    RICH = True
except ImportError:
    RICH = False

from detector import PhishingDetector, AnalysisReport, Flag

console = Console() if RICH else None

# ─── colour / style helpers ───────────────────────────────────────────────────

LEVEL_COLOR = {
    "SAFE":     "bright_green",
    "LOW":      "green",
    "MEDIUM":   "yellow",
    "HIGH":     "red",
    "CRITICAL": "bright_red",
}

SEV_COLOR = {
    "HIGH":   "red",
    "MEDIUM": "yellow",
    "LOW":    "cyan",
}

BANNER = r"""
  ____  _     _     _     _               ____       _            _
 |  _ \| |__ (_)___| |__ (_)_ __   __ _  |  _ \  ___| |_ ___  ___| |_ ___  _ __
 | |_) | '_ \| / __| '_ \| | '_ \ / _` | | | | |/ _ \ __/ _ \/ __| __/ _ \| '__|
 |  __/| | | | \__ \ | | | | | | | (_| | | |_| |  __/ ||  __/ (__| || (_) | |
 |_|   |_| |_|_|___/_| |_|_|_| |_|\__, | |____/ \___|\__\___|\___|\__\___/|_|
                                   |___/
"""


def _print(text: str = "", style: str = "") -> None:
    if RICH:
        console.print(text, style=style)
    else:
        print(text)


def _rule(title: str = "") -> None:
    if RICH:
        console.rule(title)
    else:
        print(f"\n{'─' * 60}  {title}")


# ─── display report ──────────────────────────────────────────────────────────

def display_report(report: AnalysisReport) -> None:
    if RICH:
        _display_rich(report)
    else:
        _display_plain(report)


def _display_rich(report: AnalysisReport) -> None:
    level_color = LEVEL_COLOR.get(report.risk_level, "white")

    # ── header panel ──
    header_text = Text()
    header_text.append(f"  Timestamp : ", style="dim")
    header_text.append(f"{report.timestamp}\n")
    header_text.append(f"  Subject   : ", style="dim")
    header_text.append(f"{report.subject}\n")
    header_text.append(f"  Sender    : ", style="dim")
    header_text.append(f"{report.sender}\n\n")
    header_text.append(f"  RISK SCORE : ", style="bold")
    header_text.append(f"{report.risk_score}/100  ", style=f"bold {level_color}")
    header_text.append(f"[{report.risk_level}]", style=f"bold reverse {level_color}")

    console.print(Panel(header_text, title="[bold]Email Analysis Report[/bold]", border_style=level_color))

    # ── summary ──
    console.print(f"\n  [bold]Summary:[/bold] {report.summary}\n")

    # ── flags table ──
    if report.flags:
        table = Table(
            title="Detected Issues",
            box=box.ROUNDED,
            border_style="dim",
            show_lines=True,
        )
        table.add_column("Category",    style="bold cyan",  width=22)
        table.add_column("Severity",    width=10)
        table.add_column("Description", width=52)
        table.add_column("Evidence",    style="dim",        width=34)

        for flag in sorted(report.flags, key=lambda f: ["HIGH","MEDIUM","LOW"].index(f.severity)):
            sev_color = SEV_COLOR.get(flag.severity, "white")
            table.add_row(
                flag.category,
                Text(flag.severity, style=f"bold {sev_color}"),
                flag.description,
                textwrap.shorten(flag.evidence, 60, placeholder="…"),
            )
        console.print(table)
    else:
        console.print("  [bright_green]✔  No suspicious issues flagged.[/bright_green]\n")

    # ── URLs ──
    if report.urls:
        console.print(f"\n  [bold]URLs found:[/bold] {len(report.urls)}")
        for url in report.urls:
            color = "red" if url in report.suspicious_urls else "green"
            icon  = "✗" if url in report.suspicious_urls else "✓"
            console.print(f"    [{color}]{icon}[/{color}]  {url}")

    console.print()


def _display_plain(report: AnalysisReport) -> None:
    print("\n" + "=" * 70)
    print("  EMAIL ANALYSIS REPORT")
    print("=" * 70)
    print(f"  Timestamp  : {report.timestamp}")
    print(f"  Subject    : {report.subject}")
    print(f"  Sender     : {report.sender}")
    print(f"  Risk Score : {report.risk_score}/100  [{report.risk_level}]")
    print(f"\n  Summary: {report.summary}")
    print("\n" + "-" * 70)

    if report.flags:
        print("  DETECTED ISSUES:")
        for flag in sorted(report.flags, key=lambda f: ["HIGH","MEDIUM","LOW"].index(f.severity)):
            print(f"\n  [{flag.severity}] {flag.category}")
            print(f"    {flag.description}")
            if flag.evidence:
                print(f"    Evidence: {textwrap.shorten(flag.evidence, 80, placeholder='...')}")
    else:
        print("  No suspicious issues flagged.")

    if report.urls:
        print(f"\n  URLs ({len(report.urls)} found):")
        for url in report.urls:
            mark = "[SUSPICIOUS]" if url in report.suspicious_urls else "[OK]"
            print(f"    {mark}  {url}")

    print("=" * 70 + "\n")


# ─── input modes ─────────────────────────────────────────────────────────────

def _input_manual() -> dict:
    """Prompt user to enter email fields manually."""
    _rule("Manual Input Mode")
    _print("Enter the email details below. Press Enter to skip optional fields.\n")

    sender  = input("  From (sender address) : ").strip()
    subject = input("  Subject               : ").strip()

    _print("\n  Body — paste the email body, then type END on a new line:")
    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line.strip().upper() == "END":
            break
        lines.append(line)
    body = "\n".join(lines)

    reply_to = input("\n  Reply-To (optional)   : ").strip()

    headers = {}
    if reply_to:
        headers["Reply-To"] = reply_to
        headers["From"]     = sender

    return dict(subject=subject, sender=sender, body=body, headers=headers)


def _input_file(path: str) -> str | None:
    """Read a raw .eml file."""
    p = Path(path)
    if not p.exists():
        _print(f"  [red]File not found: {path}[/red]" if RICH else f"  File not found: {path}")
        return None
    return p.read_text(errors="replace")


def _save_report(report: AnalysisReport, out_path: str) -> None:
    Path(out_path).write_text(json.dumps(report.to_dict(), indent=2))
    _print(f"\n  Report saved → {out_path}", style="dim")


# ─── main menu ───────────────────────────────────────────────────────────────

def main() -> None:
    if RICH:
        console.print(BANNER, style="bold cyan")
        console.print("  [bold]Phishing Email Detector[/bold]  •  [dim]For security research & awareness[/dim]\n")
    else:
        print(BANNER)
        print("  Phishing Email Detector  •  For security research & awareness\n")

    detector = PhishingDetector()

    while True:
        _rule("Main Menu")
        _print("  [1]  Analyse email — manual input (paste fields)")
        _print("  [2]  Analyse .eml file")
        _print("  [3]  Run built-in demo examples")
        _print("  [4]  Quit")
        _print()

        choice = input("  Choose [1-4]: ").strip()

        if choice == "1":
            data   = _input_manual()
            report = detector.analyze_fields(**data)
            display_report(report)
            _maybe_save(report)

        elif choice == "2":
            path = input("  Path to .eml file: ").strip().strip('"')
            raw = _input_file(path)
            if raw:
                report = detector.analyze_raw(raw)
                display_report(report)
                _maybe_save(report)

        elif choice == "3":
            run_demos(detector)

        elif choice == "4":
            _print("\n  Goodbye.\n", style="dim")
            sys.exit(0)

        else:
            _print("  Invalid choice.", style="red")


def _maybe_save(report: AnalysisReport) -> None:
    ans = input("  Save report to JSON? [y/N]: ").strip().lower()
    if ans == "y":
        default = f"report_{report.timestamp.replace(' ', '_').replace(':', '-')}.json"
        path = input(f"  Filename [{default}]: ").strip() or default
        _save_report(report, path)


# ─── built-in demo samples ────────────────────────────────────────────────────

DEMO_EMAILS = [
    {
        "label": "Classic PayPal phish",
        "sender": "PayPal Support <security-alert@paypa1-support.xyz>",
        "subject": "URGENT: Your PayPal Account Has Been Suspended!",
        "body": (
            "Dear Valued Customer,\n\n"
            "We have detected suspicious activity on your PayPal account. "
            "Your account has been suspended. You must verify your credentials immediately "
            "to restore access.\n\n"
            "Click here to verify your account now: http://paypa1-secure.xyz/login?id=8821\n\n"
            "Failure to act now will result in permanent account closure.\n\n"
            "PayPal Security Team"
        ),
    },
    {
        "label": "Fake IT department password reset",
        "sender": "IT Department <it-helpdesk@gmail.com>",
        "subject": "ACTION REQUIRED: Reset Your Password NOW",
        "body": (
            "Hello,\n\n"
            "Your corporate password expires in 24 hours. "
            "Please click the link below to reset your password immediately:\n\n"
            "http://bit.ly/reset-corp-pass\n\n"
            "Enter your username, current password, and new password on the form.\n\n"
            "IT Support"
        ),
        "headers": {
            "From": "IT Department <it-helpdesk@gmail.com>",
            "Reply-To": "attacker@evil.tk",
        },
    },
    {
        "label": "Legitimate-looking newsletter (low risk)",
        "sender": "newsletter@medium.com",
        "subject": "Your weekly reading digest",
        "body": (
            "Hi there,\n\n"
            "Here are your top stories this week from Medium.\n\n"
            "1. How to write better Python code — https://medium.com/article/python\n"
            "2. Understanding async/await — https://medium.com/article/async\n\n"
            "Unsubscribe: https://medium.com/unsubscribe\n\n"
            "Medium, 760 Market St, San Francisco, CA"
        ),
    },
    {
        "label": "Prize scam",
        "sender": "Rewards Center <rewards@lucky-draw.top>",
        "subject": "Congratulations!! You have WON a FREE iPhone 15!!!",
        "body": (
            "You have been selected as our lucky winner!\n\n"
            "Claim your FREE iPhone 15 now — limited time offer expires soon!\n\n"
            "Click here: http://192.168.1.100/claim?token=abc123\n\n"
            "Provide your full name, date of birth, and credit card number to "
            "cover the small shipping fee.\n\n"
            "Act now before your prize is given to someone else!"
        ),
    },
]


def run_demos(detector: PhishingDetector) -> None:
    _rule("Demo Examples")
    for i, demo in enumerate(DEMO_EMAILS, 1):
        _print(f"\n  [bold cyan]Demo {i}/{len(DEMO_EMAILS)}[/bold cyan] — {demo['label']}" if RICH
               else f"\n  Demo {i}/{len(DEMO_EMAILS)} — {demo['label']}")

        report = detector.analyze_fields(
            subject=demo["subject"],
            sender=demo["sender"],
            body=demo["body"],
            headers=demo.get("headers", {}),
        )
        display_report(report)

        if i < len(DEMO_EMAILS):
            inp = input("  Press Enter for next demo (or 'q' to stop): ").strip().lower()
            if inp == "q":
                break


if __name__ == "__main__":
    main()
