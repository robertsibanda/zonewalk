import sys
from datetime import datetime
from typing import Optional


class Style:
    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    YELLOW = "\033[1;33m"
    BLUE = "\033[0;34m"
    CYAN = "\033[0;36m"
    MAGENTA = "\033[1;35m"
    WHITE = "\033[1;37m"
    GRAY = "\033[0;90m"
    NC = "\033[0m"

    OK = f"{GREEN}OK{NC}"
    FAIL = f"{RED}FAIL{NC}"
    WARN = f"{YELLOW}WARN{NC}"
    INFO = f"{CYAN}INFO{NC}"


def header(title: str) -> None:
    print(f"\n{Style.BLUE}{'=' * 50}{Style.NC}")
    print(f"{Style.WHITE}  {title}{Style.NC}")
    print(f"{Style.BLUE}{'=' * 50}{Style.NC}")


def section(title: str) -> None:
    print(f"\n{Style.MAGENTA}>> {title}{Style.NC}")
    print(f"{Style.MAGENTA}{'-' * 50}{Style.NC}")


def subsection(title: str) -> None:
    print(f"\n  {Style.CYAN}* {title}{Style.NC}")


def note(msg: str) -> None:
    print(f"  {Style.GRAY}-> {msg}{Style.NC}")


def ok(msg: str) -> None:
    print(f"  {Style.OK} {msg}")


def fail(msg: str) -> None:
    print(f"  {Style.FAIL} {msg}")


def warn(msg: str) -> None:
    print(f"  {Style.WARN} {msg}")


def info(msg: str) -> None:
    print(f"  {Style.INFO} {msg}")


def days_until(date_str: str) -> Optional[int]:
    try:
        exp = datetime.strptime(date_str.split("T")[0], "%Y-%m-%d")
        return (exp - datetime.now()).days
    except (ValueError, IndexError):
        return None


def plural(n: int, word: str) -> str:
    return f"{n} {word}{'s' if n != 1 else ''}"
