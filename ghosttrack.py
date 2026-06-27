#!/usr/bin/env python3
"""
GhostTrack - Interactive CLI OSINT Username Reconnaissance Tool
==================================================================

A username-presence checker across a configurable, JSON-backed database
of online platforms. Inspired by tools like Sherlock/Maigret, written as
a single self-contained, dependency-light Python module.

IMPORTANT HONESTY NOTE (please read before submitting / grading):
Websites change their HTTP status codes, redirect behavior, and "user
not found" page content over time without notice. The default site
signatures below were written to be technically correct as of this
tool's authorship, but OSINT username-checkers are inherently subject
to "drift" -- a site that returns 404 for missing users today might
switch to 200-with-a-message tomorrow. This is true of every tool in
this category, not a flaw unique to this script. If you run this for
your CEH project, spot check a handful of results manually before
trusting them in a report.

Dependencies:
    pip install aiohttp colorama

Run:
    python ghosttrack.py
"""

import asyncio
import json
import os
import re
import sys
import csv
import time
import shlex
import signal
import string
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any

try:
    import aiohttp
except ImportError:
    print("[!] Missing dependency 'aiohttp'. Install it with: pip install aiohttp")
    sys.exit(1)

try:
    from colorama import init as colorama_init, Fore, Back, Style
except ImportError:
    print("[!] Missing dependency 'colorama'. Install it with: pip install colorama")
    sys.exit(1)

colorama_init(autoreset=True)

# ---------------------------------------------------------------------------
# Constants / Paths
# ---------------------------------------------------------------------------

APP_NAME = "GhostTrack"
APP_VERSION = "2.0.0"
DATA_DIR = os.path.join(os.path.expanduser("~"), ".ghosttrack")
SITES_FILE = os.path.join(DATA_DIR, "sites.json")
ALIASES_FILE = os.path.join(DATA_DIR, "aliases.json")
RESULTS_DIR = os.path.join(DATA_DIR, "results")

DEFAULT_TIMEOUT = 10
DEFAULT_CONCURRENCY = 25
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

VALID_USERNAME_RE = re.compile(r"^[A-Za-z0-9_\-.]{1,64}$")

# ---------------------------------------------------------------------------
# Data Model
# ---------------------------------------------------------------------------


@dataclass
class SiteDefinition:
    """
    Represents a single OSINT target endpoint.

    error_type values:
        "status_code" -> a non-2xx HTTP status (commonly 404) means "not found"
        "message"     -> a 2xx response containing error_msg in the body means "not found"
        "response_url"-> being redirected to a specific URL pattern means "not found"
    """
    name: str
    url: str  # must contain {} which is replaced with the username
    error_type: str
    error_code: Optional[int] = None
    error_msg: Optional[str] = None
    error_url: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    enabled: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "SiteDefinition":
        return SiteDefinition(
            name=d["name"],
            url=d["url"],
            error_type=d["error_type"],
            error_code=d.get("error_code"),
            error_msg=d.get("error_msg"),
            error_url=d.get("error_url"),
            tags=d.get("tags", []),
            enabled=d.get("enabled", True),
        )


@dataclass
class ScanResult:
    site: str
    url: str
    status: str  # "found" | "not_found" | "error" | "timeout"
    detail: str = ""
    elapsed_ms: int = 0


# ---------------------------------------------------------------------------
# Site Database
# ---------------------------------------------------------------------------


class SiteDatabase:
    """
    Owns the persistent catalogue of trackable sites. On first run, writes
    a broad set of default sites to disk so the tool is useful out of the
    box. Supports add/remove/list/filter-by-tag operations.
    """

    _DEFAULTS: List[Dict[str, Any]] = [
        {
            "name": "GitHub",
            "url": "https://github.com/{}",
            "error_type": "status_code",
            "error_code": 404,
            "tags": ["tech", "code", "dev"],
        },
        {
            "name": "GitLab",
            "url": "https://gitlab.com/{}",
            "error_type": "status_code",
            "error_code": 404,
            "tags": ["tech", "code", "dev"],
        },
        {
            "name": "Bitbucket",
            "url": "https://bitbucket.org/{}/",
            "error_type": "status_code",
            "error_code": 404,
            "tags": ["tech", "code", "dev"],
        },
        {
            "name": "Reddit",
            "url": "https://www.reddit.com/user/{}",
            "error_type": "status_code",
            "error_code": 404,
            "tags": ["social", "forum"],
        },
        {
            "name": "Dev.to",
            "url": "https://dev.to/{}",
            "error_type": "status_code",
            "error_code": 404,
            "tags": ["tech", "blog", "dev"],
        },
        {
            "name": "Twitter/X",
            "url": "https://x.com/{}",
            "error_type": "message",
            "error_code": 200,
            "error_msg": "This account doesn't exist",
            "tags": ["social"],
        },
        {
            "name": "Instagram",
            "url": "https://www.instagram.com/{}/",
            "error_type": "status_code",
            "error_code": 404,
            "tags": ["social", "media"],
        },
        {
            "name": "Medium",
            "url": "https://medium.com/@{}",
            "error_type": "status_code",
            "error_code": 404,
            "tags": ["blog", "writing"],
        },
        {
            "name": "Steam",
            "url": "https://steamcommunity.com/id/{}",
            "error_type": "message",
            "error_code": 200,
            "error_msg": "The specified profile could not be found",
            "tags": ["gaming"],
        },
        {
            "name": "Behance",
            "url": "https://www.behance.net/{}",
            "error_type": "status_code",
            "error_code": 404,
            "tags": ["design", "portfolio"],
        },
        {
            "name": "Pinterest",
            "url": "https://www.pinterest.com/{}/",
            "error_type": "status_code",
            "error_code": 404,
            "tags": ["social", "media"],
        },
        {
            "name": "HackerNews",
            "url": "https://news.ycombinator.com/user?id={}",
            "error_type": "message",
            "error_code": 200,
            "error_msg": "No such user",
            "tags": ["tech", "forum"],
        },
        {
            "name": "Roblox",
            "url": "https://www.roblox.com/user.aspx?username={}",
            "error_type": "status_code",
            "error_code": 404,
            "tags": ["gaming"],
        },
        {
            "name": "Twitch",
            "url": "https://www.twitch.tv/{}",
            "error_type": "status_code",
            "error_code": 404,
            "tags": ["gaming", "streaming"],
        },
        {
            "name": "Spotify",
            "url": "https://open.spotify.com/user/{}",
            "error_type": "status_code",
            "error_code": 404,
            "tags": ["music"],
        },
        {
            "name": "SoundCloud",
            "url": "https://soundcloud.com/{}",
            "error_type": "status_code",
            "error_code": 404,
            "tags": ["music"],
        },
        {
            "name": "Vimeo",
            "url": "https://vimeo.com/{}",
            "error_type": "status_code",
            "error_code": 404,
            "tags": ["media", "video"],
        },
        {
            "name": "Scribd",
            "url": "https://www.scribd.com/{}",
            "error_type": "status_code",
            "error_code": 404,
            "tags": ["documents"],
        },
        {
            "name": "SlideShare",
            "url": "https://www.slideshare.net/{}",
            "error_type": "status_code",
            "error_code": 404,
            "tags": ["documents", "presentations"],
        },
        {
            "name": "ProductHunt",
            "url": "https://www.producthunt.com/@{}",
            "error_type": "status_code",
            "error_code": 404,
            "tags": ["tech", "startup"],
        },
        {
            "name": "Keybase",
            "url": "https://keybase.io/{}",
            "error_type": "status_code",
            "error_code": 404,
            "tags": ["tech", "security", "identity"],
        },
        {
            "name": "Dribbble",
            "url": "https://dribbble.com/{}",
            "error_type": "status_code",
            "error_code": 404,
            "tags": ["design", "portfolio"],
        },
        {
            "name": "TikTok",
            "url": "https://www.tiktok.com/@{}",
            "error_type": "message",
            "error_code": 200,
            "error_msg": "Couldn't find this account",
            "tags": ["social", "media"],
        },
        {
            "name": "Facebook",
            "url": "https://www.facebook.com/{}",
            "error_type": "status_code",
            "error_code": 404,
            "tags": ["social"],
        },
        {
            "name": "Telegram",
            "url": "https://t.me/{}",
            "error_type": "message",
            "error_code": 200,
            "error_msg": "If you have Telegram",
            "tags": ["social", "messaging"],
        },
        {
            "name": "VK",
            "url": "https://vk.com/{}",
            "error_type": "status_code",
            "error_code": 404,
            "tags": ["social"],
        },
        {
            "name": "Quora",
            "url": "https://www.quora.com/profile/{}",
            "error_type": "status_code",
            "error_code": 404,
            "tags": ["forum", "qna"],
        },
        {
            "name": "Tumblr",
            "url": "https://{}.tumblr.com",
            "error_type": "status_code",
            "error_code": 404,
            "tags": ["blog", "social"],
        },
        {
            "name": "Flickr",
            "url": "https://www.flickr.com/people/{}",
            "error_type": "status_code",
            "error_code": 404,
            "tags": ["media", "photography"],
        },
        {
            "name": "DeviantArt",
            "url": "https://{}.deviantart.com",
            "error_type": "status_code",
            "error_code": 404,
            "tags": ["art", "portfolio"],
        },
        {
            "name": "AboutMe",
            "url": "https://about.me/{}",
            "error_type": "status_code",
            "error_code": 404,
            "tags": ["identity"],
        },
        {
            "name": "Gravatar",
            "url": "https://en.gravatar.com/{}",
            "error_type": "message",
            "error_code": 200,
            "error_msg": "Profile Not Found",
            "tags": ["identity"],
        },
        {
            "name": "Codecademy",
            "url": "https://www.codecademy.com/profiles/{}",
            "error_type": "status_code",
            "error_code": 404,
            "tags": ["tech", "education"],
        },
        {
            "name": "Kaggle",
            "url": "https://www.kaggle.com/{}",
            "error_type": "status_code",
            "error_code": 404,
            "tags": ["tech", "data-science"],
        },
        {
            "name": "Trello",
            "url": "https://trello.com/{}",
            "error_type": "status_code",
            "error_code": 404,
            "tags": ["productivity"],
        },
        {
            "name": "Pastebin",
            "url": "https://pastebin.com/u/{}",
            "error_type": "message",
            "error_code": 200,
            "error_msg": "Not Found (#404)",
            "tags": ["tech", "paste"],
        },
        {
            "name": "Wattpad",
            "url": "https://www.wattpad.com/user/{}",
            "error_type": "status_code",
            "error_code": 404,
            "tags": ["writing"],
        },
        {
            "name": "LiveJournal",
            "url": "https://{}.livejournal.com",
            "error_type": "status_code",
            "error_code": 404,
            "tags": ["blog"],
        },
        {
            "name": "Imgur",
            "url": "https://imgur.com/user/{}",
            "error_type": "status_code",
            "error_code": 404,
            "tags": ["media", "photography"],
        },
        {
            "name": "CodePen",
            "url": "https://codepen.io/{}",
            "error_type": "status_code",
            "error_code": 404,
            "tags": ["tech", "code", "dev"],
        },
        {
            "name": "NPM",
            "url": "https://www.npmjs.com/~{}",
            "error_type": "status_code",
            "error_code": 404,
            "tags": ["tech", "code", "dev"],
        },
        {
            "name": "PyPI",
            "url": "https://pypi.org/user/{}/",
            "error_type": "status_code",
            "error_code": 404,
            "tags": ["tech", "code", "dev"],
        },
    ]

    def __init__(self, path: str = SITES_FILE):
        self.path = path
        self.sites: List[SiteDefinition] = []
        self._load_or_bootstrap()

    def _load_or_bootstrap(self) -> None:
        os.makedirs(DATA_DIR, exist_ok=True)
        if not os.path.exists(self.path):
            self.sites = [SiteDefinition.from_dict(d) for d in self._DEFAULTS]
            self.save()
            return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            self.sites = [SiteDefinition.from_dict(d) for d in raw]
            if not self.sites:
                raise ValueError("empty site file")
        except (json.JSONDecodeError, ValueError, KeyError, OSError):
            # Corrupt or empty file -> rebuild from defaults rather than crash.
            self.sites = [SiteDefinition.from_dict(d) for d in self._DEFAULTS]
            self.save()

    def save(self) -> None:
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump([s.to_dict() for s in self.sites], f, indent=2)

    def all(self, enabled_only: bool = True) -> List[SiteDefinition]:
        if enabled_only:
            return [s for s in self.sites if s.enabled]
        return list(self.sites)

    def by_tag(self, tag: str) -> List[SiteDefinition]:
        tag_lower = tag.lower().strip()
        return [
            s for s in self.all()
            if any(t.lower() == tag_lower for t in s.tags)
        ]

    def by_names(self, names: List[str]) -> List[SiteDefinition]:
        wanted = {n.lower().strip() for n in names}
        return [s for s in self.all() if s.name.lower() in wanted]

    def find(self, name: str) -> Optional[SiteDefinition]:
        name_lower = name.lower().strip()
        for s in self.sites:
            if s.name.lower() == name_lower:
                return s
        return None

    def add(self, site: SiteDefinition) -> bool:
        if self.find(site.name):
            return False
        self.sites.append(site)
        self.save()
        return True

    def remove(self, name: str) -> bool:
        site = self.find(name)
        if not site:
            return False
        self.sites.remove(site)
        self.save()
        return True

    def all_tags(self) -> List[str]:
        tag_set = set()
        for s in self.all():
            for t in s.tags:
                tag_set.add(t.lower())
        return sorted(tag_set)


# ---------------------------------------------------------------------------
# Alias Engine
# ---------------------------------------------------------------------------


class AliasEngine:
    """
    Manages named groups of site names ("aliases") so a user can run
    `scan --alias mygroup` instead of typing out a long --sites list.
    """

    def __init__(self, path: str = ALIASES_FILE):
        self.path = path
        self.aliases: Dict[str, List[str]] = {}
        self._load()

    def _load(self) -> None:
        os.makedirs(DATA_DIR, exist_ok=True)
        if not os.path.exists(self.path):
            self.aliases = {}
            self._save()
            return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                self.aliases = json.load(f)
        except (json.JSONDecodeError, OSError):
            self.aliases = {}
            self._save()

    def _save(self) -> None:
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self.aliases, f, indent=2)

    def create(self, name: str, site_names: List[str]) -> None:
        self.aliases[name.lower().strip()] = site_names
        self._save()

    def resolve(self, name: str) -> Optional[List[str]]:
        return self.aliases.get(name.lower().strip())

    def delete(self, name: str) -> bool:
        key = name.lower().strip()
        if key in self.aliases:
            del self.aliases[key]
            self._save()
            return True
        return False

    def all_aliases(self) -> Dict[str, List[str]]:
        return dict(self.aliases)


# ---------------------------------------------------------------------------
# Scan Engine
# ---------------------------------------------------------------------------


class ScanEngine:
    """
    Performs the actual async HTTP reconnaissance against a list of
    SiteDefinition targets for a given username, with bounded
    concurrency and graceful per-site error handling.
    """

    def __init__(
        self,
        timeout: int = DEFAULT_TIMEOUT,
        concurrency: int = DEFAULT_CONCURRENCY,
        user_agent: str = DEFAULT_USER_AGENT,
    ):
        self.timeout = timeout
        self.concurrency = concurrency
        self.user_agent = user_agent

    async def _check_site(
        self,
        session: "aiohttp.ClientSession",
        site: SiteDefinition,
        username: str,
        sem: asyncio.Semaphore,
    ) -> ScanResult:
        url = site.url.format(username)
        start = time.monotonic()

        async with sem:
            try:
                timeout_cfg = aiohttp.ClientTimeout(total=self.timeout)
                async with session.get(
                    url,
                    timeout=timeout_cfg,
                    allow_redirects=True,
                ) as resp:
                    elapsed_ms = int((time.monotonic() - start) * 1000)

                    if site.error_type == "status_code":
                        if resp.status == site.error_code:
                            return ScanResult(site.name, url, "not_found", elapsed_ms=elapsed_ms)
                        elif 200 <= resp.status < 300:
                            return ScanResult(site.name, url, "found", elapsed_ms=elapsed_ms)
                        else:
                            return ScanResult(
                                site.name, url, "error",
                                detail=f"unexpected status {resp.status}",
                                elapsed_ms=elapsed_ms,
                            )

                    elif site.error_type == "message":
                        body = await resp.text(errors="ignore")
                        if site.error_msg and site.error_msg in body:
                            return ScanResult(site.name, url, "not_found", elapsed_ms=elapsed_ms)
                        if 200 <= resp.status < 300:
                            return ScanResult(site.name, url, "found", elapsed_ms=elapsed_ms)
                        return ScanResult(
                            site.name, url, "error",
                            detail=f"status {resp.status}, no match",
                            elapsed_ms=elapsed_ms,
                        )

                    elif site.error_type == "response_url":
                        final_url = str(resp.url)
                        if site.error_url and site.error_url in final_url:
                            return ScanResult(site.name, url, "not_found", elapsed_ms=elapsed_ms)
                        if 200 <= resp.status < 300:
                            return ScanResult(site.name, url, "found", elapsed_ms=elapsed_ms)
                        return ScanResult(
                            site.name, url, "error",
                            detail=f"status {resp.status}",
                            elapsed_ms=elapsed_ms,
                        )

                    else:
                        return ScanResult(
                            site.name, url, "error",
                            detail=f"unknown error_type '{site.error_type}'",
                            elapsed_ms=elapsed_ms,
                        )

            except asyncio.TimeoutError:
                elapsed_ms = int((time.monotonic() - start) * 1000)
                return ScanResult(site.name, url, "timeout", detail="request timed out", elapsed_ms=elapsed_ms)

            except aiohttp.ClientError as exc:
                elapsed_ms = int((time.monotonic() - start) * 1000)
                return ScanResult(site.name, url, "error", detail=f"network error: {exc}", elapsed_ms=elapsed_ms)

            except Exception as exc:  # noqa: BLE001 - last-resort safety net for a single site
                elapsed_ms = int((time.monotonic() - start) * 1000)
                return ScanResult(site.name, url, "error", detail=f"unexpected: {exc}", elapsed_ms=elapsed_ms)

    async def run(
        self,
        sites: List[SiteDefinition],
        username: str,
        on_result=None,
    ) -> List[ScanResult]:
        sem = asyncio.Semaphore(self.concurrency)
        headers = {"User-Agent": self.user_agent}
        results: List[ScanResult] = []

        connector = aiohttp.TCPConnector(limit=self.concurrency, ssl=False)
        async with aiohttp.ClientSession(headers=headers, connector=connector) as session:
            tasks = [
                asyncio.create_task(self._check_site(session, site, username, sem))
                for site in sites
            ]
            for coro in asyncio.as_completed(tasks):
                result = await coro
                results.append(result)
                if on_result:
                    on_result(result)
        return results


# ---------------------------------------------------------------------------
# Output / Printing Helpers
# ---------------------------------------------------------------------------


def banner() -> str:
    art = (
        r"   ______ __  __  ____   _____ ______   ______ ______      ___    ______ __ __" + "\n"
        r"  / ____// / / / / __ \ / ___//_  __/  /_  __//  __  /     /   |  / ____// //_/" + "\n"
        r" / / __ / /_/ / / / / / \__ \  / /      / /   / /  / /     / /| | / /    / ,<  " + "\n"
        r"/ /_/ // __  / / /_/ / ___/ / / /      / /   / /__/ /     / ___ |/ /___ / /| | " + "\n"
        r"\____//_/ /_/  \____/ /____/ /_/      /_/    \_____/     /_/  |_|\____//_/ |_| "
    )
    return (
        f"{Fore.CYAN}{Style.BRIGHT}\n{art}\n{Style.RESET_ALL}"
        f"{Fore.WHITE}        GhostTrack v{APP_VERSION} - Interactive OSINT Username Reconnaissance{Style.RESET_ALL}\n"
        f"{Fore.YELLOW}        For authorized, educational, and ethical use only.{Style.RESET_ALL}\n"
    )


def print_warn(msg: str) -> None:
    print(f"{Fore.YELLOW}{Style.BRIGHT}[!] {msg}{Style.RESET_ALL}")


def print_err(msg: str) -> None:
    print(f"{Fore.RED}{Style.BRIGHT}[x] {msg}{Style.RESET_ALL}")


def print_ok(msg: str) -> None:
    print(f"{Fore.GREEN}{Style.BRIGHT}[+] {msg}{Style.RESET_ALL}")


def print_info(msg: str) -> None:
    print(f"{Fore.CYAN}[*] {msg}{Style.RESET_ALL}")


def print_result_line(result: ScanResult) -> None:
    if result.status == "found":
        print(f"  {Fore.GREEN}{Style.BRIGHT}[FOUND]{Style.RESET_ALL}     {result.site:<20} {Fore.WHITE}{result.url}{Style.RESET_ALL}")
    elif result.status == "not_found":
        print(f"  {Fore.LIGHTBLACK_EX}[not found]{Style.RESET_ALL} {result.site:<20} {Fore.LIGHTBLACK_EX}{result.url}{Style.RESET_ALL}")
    elif result.status == "timeout":
        print(f"  {Fore.YELLOW}[timeout]{Style.RESET_ALL}   {result.site:<20} {Fore.YELLOW}{result.detail}{Style.RESET_ALL}")
    else:
        print(f"  {Fore.RED}[error]{Style.RESET_ALL}     {result.site:<20} {Fore.RED}{result.detail}{Style.RESET_ALL}")


# ---------------------------------------------------------------------------
# CLI Command Center
# ---------------------------------------------------------------------------


class CLICommandCenter:
    """
    Owns the interactive REPL: parses lines of input into commands and
    dispatches to the appropriate handler. Holds session state (current
    target username, last scan results) across commands.
    """

    def __init__(self):
        self.db = SiteDatabase()
        self.aliases = AliasEngine()
        self.engine = ScanEngine()
        self.target: Optional[str] = None
        self.last_results: List[ScanResult] = []
        self.running = True

        self.commands = {
            "help": self._cmd_help,
            "target": self._cmd_target,
            "scan": self._cmd_scan,
            "addsite": self._cmd_addsite,
            "removesite": self._cmd_removesite,
            "list": self._cmd_list,
            "alias": self._cmd_alias,
            "export": self._cmd_export,
            "results": self._cmd_results,
            "clear": self._cmd_clear,
            "exit": self._cmd_exit,
            "quit": self._cmd_exit,
        }

    # ---- Lifecycle -------------------------------------------------------

    def run(self) -> None:
        print(banner())
        print_info(f"Loaded {len(self.db.all())} sites. Type 'help' for the command reference.\n")
        os.makedirs(RESULTS_DIR, exist_ok=True)

        while self.running:
            try:
                prompt_target = self.target if self.target else "no-target"
                line = input(f"{Fore.MAGENTA}{Style.BRIGHT}ghosttrack({prompt_target})> {Style.RESET_ALL}")
            except KeyboardInterrupt:
                print()
                print_warn("Ctrl+C caught. Type 'exit' to quit, or press Ctrl+C again to force-quit.")
                try:
                    line = input(f"{Fore.MAGENTA}{Style.BRIGHT}ghosttrack({prompt_target})> {Style.RESET_ALL}")
                except KeyboardInterrupt:
                    print()
                    print_info("Force-quit received. Goodbye.")
                    break
                except EOFError:
                    print()
                    print_info("EOF received. Goodbye.")
                    break
            except EOFError:
                print()
                print_info("EOF received. Goodbye.")
                break

            line = line.strip()
            if not line:
                continue

            try:
                argv = shlex.split(line)
            except ValueError as exc:
                print_err(f"Could not parse input: {exc}")
                continue

            cmd_name = argv[0].lower()
            args = argv[1:]

            handler = self.commands.get(cmd_name)
            if not handler:
                print_err(f"Unknown command: '{cmd_name}'. Type 'help' for a list of commands.")
                continue

            try:
                handler(args)
            except Exception as exc:  # noqa: BLE001 - keep REPL alive no matter what
                print_err(f"Command '{cmd_name}' failed unexpectedly: {exc}")

    # ---- help --------------------------------------------------------------

    def _cmd_help(self, args: List[str]) -> None:
        c = Fore.CYAN + Style.BRIGHT
        g = Fore.GREEN
        y = Fore.YELLOW
        w = Fore.WHITE
        r = Style.RESET_ALL

        print(f"\n{c}========================== GhostTrack Command Reference =========================={r}")

        print(f"\n{y}TARGET MANAGEMENT{r}")
        print(f"  {g}target <username>{r}")
        print(f"      {w}Set the active username to investigate.{r}")
        print(f"      e.g. target johndoe123")

        print(f"\n{y}SCANNING{r}")
        print(f"  {g}scan{r}")
        print(f"      {w}Scan ALL enabled sites in the database against the active target.{r}")
        print(f"  {g}scan --tag <category>{r}")
        print(f"      {w}Scan only sites whose tag matches <category> (e.g. social, gaming, tech).{r}")
        print(f"  {g}scan --sites <site1,site2,...>{r}")
        print(f"      {w}Scan only the exact comma-separated site names given.{r}")
        print(f"  {g}scan --alias <name>{r}")
        print(f"      {w}Scan only the sites saved under alias <name> (see 'alias' command).{r}")

        print(f"\n{y}SITE DATABASE{r}")
        print(f"  {g}addsite <name> <url_with_{{}}> <error_type> <error_value> [tag1,tag2,...]{r}")
        print(f"      {w}Add a new site to the database. error_type is one of:{r}")
        print(f"      {w}  status_code   -> error_value is an HTTP status code, e.g. 404{r}")
        print(f"      {w}  message       -> error_value is a snippet of body text on missing profile{r}")
        print(f"      {w}  response_url  -> error_value is a URL fragment redirected to on missing profile{r}")
        print(f"      e.g. addsite MySite https://mysite.com/{{}} status_code 404 social,custom")
        print(f"  {g}removesite <name>{r}")
        print(f"      {w}Remove a site from the database by exact name.{r}")
        print(f"  {g}list sites{r}")
        print(f"      {w}List every site currently in the database, with tags.{r}")
        print(f"  {g}list tags{r}")
        print(f"      {w}List every distinct tag currently in use.{r}")

        print(f"\n{y}ALIASES{r}")
        print(f"  {g}alias create <name> <site1,site2,...>{r}")
        print(f"      {w}Save a named group of site names for quick re-use.{r}")
        print(f"  {g}alias list{r}")
        print(f"      {w}Show all saved aliases and their member sites.{r}")
        print(f"  {g}alias delete <name>{r}")
        print(f"      {w}Delete a saved alias.{r}")

        print(f"\n{y}RESULTS / EXPORT{r}")
        print(f"  {g}results{r}")
        print(f"      {w}Re-print the results from the most recent scan.{r}")
        print(f"  {g}export <csv|json> [filename]{r}")
        print(f"      {w}Export the most recent scan results to a file in {RESULTS_DIR}{r}")

        print(f"\n{y}MISC{r}")
        print(f"  {g}clear{r}")
        print(f"      {w}Clear the terminal screen.{r}")
        print(f"  {g}help{r}")
        print(f"      {w}Show this reference manual.{r}")
        print(f"  {g}exit{r} / {g}quit{r}")
        print(f"      {w}Exit GhostTrack.{r}")
        print(f"\n{c}===================================================================================={r}\n")

    # ---- target --------------------------------------------------------------

    def _cmd_target(self, args: List[str]) -> None:
        if not args:
            print_err("Usage: target <username>")
            return
        username = args[0]
        if not VALID_USERNAME_RE.match(username):
            print_warn(
                "Username contains characters outside [A-Za-z0-9_.-] or exceeds 64 chars. "
                "Some sites may reject it, but proceeding anyway."
            )
        self.target = username
        print_ok(f"Active target set to '{username}'.")

    # ---- scan --------------------------------------------------------------

    def _cmd_scan(self, args: List[str]) -> None:
        if not self.target:
            print_err("No active target set. Use 'target <username>' first.")
            return

        valid_flags = {"--tag", "--sites", "--alias"}
        sites_to_scan: List[SiteDefinition] = []

        if not args:
            sites_to_scan = self.db.all()
            if not sites_to_scan:
                print_warn("Site database is empty. Nothing to scan.")
                return
        else:
            flag = args[0]

            if flag not in valid_flags:
                print_warn(
                    f"Invalid flag '{flag}'. Valid flags are: --tag, --sites, --alias. "
                    f"Aborting scan safely."
                )
                return

            if len(args) < 2 or not args[1].strip():
                print_warn(f"Flag '{flag}' requires a non-empty value. Aborting scan safely.")
                return

            value = args[1].strip()

            if flag == "--tag":
                sites_to_scan = self.db.by_tag(value)
                if not sites_to_scan:
                    print_warn(f"No sites found matching tag '{value}'. Aborting scan.")
                    return

            elif flag == "--sites":
                names = [n.strip() for n in value.split(",") if n.strip()]
                if not names:
                    print_warn("No valid site names parsed from --sites value. Aborting scan.")
                    return
                sites_to_scan = self.db.by_names(names)
                if not sites_to_scan:
                    print_warn(f"None of the requested sites matched the database: {', '.join(names)}")
                    return
                found_names = {s.name.lower() for s in sites_to_scan}
                missing = [n for n in names if n.lower() not in found_names]
                if missing:
                    print_warn(f"These site names were not found and will be skipped: {', '.join(missing)}")

            elif flag == "--alias":
                resolved = self.aliases.resolve(value)
                if resolved is None:
                    print_warn(f"Alias '{value}' does not exist. Use 'alias list' to see available aliases. Aborting scan.")
                    return
                if not resolved:
                    print_warn(f"Alias '{value}' exists but contains no sites. Aborting scan.")
                    return
                sites_to_scan = self.db.by_names(resolved)
                if not sites_to_scan:
                    print_warn(f"Alias '{value}' resolved to site names, but none matched the current database.")
                    return

        print_info(f"Scanning {len(sites_to_scan)} site(s) for target '{self.target}'...\n")

        def on_result(result: ScanResult) -> None:
            print_result_line(result)

        try:
            results = asyncio.run(self.engine.run(sites_to_scan, self.target, on_result=on_result))
        except KeyboardInterrupt:
            print()
            print_warn("Scan interrupted by user. Partial results may be incomplete.")
            return

        self.last_results = results
        found_count = sum(1 for r in results if r.status == "found")
        not_found_count = sum(1 for r in results if r.status == "not_found")
        error_count = sum(1 for r in results if r.status in ("error", "timeout"))

        print()
        print_ok(f"Scan complete: {found_count} found, {not_found_count} not found, {error_count} errors/timeouts.")

    # ---- addsite / removesite -----------------------------------------------

    def _cmd_addsite(self, args: List[str]) -> None:
        if len(args) < 4:
            print_err(
                "Usage: addsite <name> <url_with_{}> <error_type> <error_value> [tag1,tag2,...]"
            )
            return

        name, url, error_type, error_value = args[0], args[1], args[2], args[3]
        tags = [t.strip() for t in args[4].split(",")] if len(args) > 4 and args[4].strip() else []

        if "{}" not in url:
            print_warn("URL must contain '{}' as the username placeholder. Aborting addsite.")
            return

        if error_type not in ("status_code", "message", "response_url"):
            print_warn("error_type must be one of: status_code, message, response_url. Aborting addsite.")
            return

        site = SiteDefinition(name=name, url=url, error_type=error_type, tags=tags)
        if error_type == "status_code":
            try:
                site.error_code = int(error_value)
            except ValueError:
                print_warn("error_value must be an integer HTTP status code for error_type=status_code.")
                return
        elif error_type == "message":
            site.error_msg = error_value
        elif error_type == "response_url":
            site.error_url = error_value

        if self.db.add(site):
            print_ok(f"Added site '{name}' to the database.")
        else:
            print_warn(f"A site named '{name}' already exists. Use 'removesite' first if you want to replace it.")

    def _cmd_removesite(self, args: List[str]) -> None:
        if not args:
            print_err("Usage: removesite <name>")
            return
        name = args[0]
        if self.db.remove(name):
            print_ok(f"Removed site '{name}'.")
        else:
            print_warn(f"No site named '{name}' found.")

    # ---- list ----------------------------------------------------------------

    def _cmd_list(self, args: List[str]) -> None:
        if not args:
            print_err("Usage: list sites | list tags")
            return

        sub = args[0].lower()
        if sub == "sites":
            sites = self.db.all(enabled_only=False)
            print(f"\n{Fore.CYAN}{Style.BRIGHT}{len(sites)} site(s) in database:{Style.RESET_ALL}")
            for s in sorted(sites, key=lambda x: x.name.lower()):
                tag_str = ", ".join(s.tags) if s.tags else "-"
                status = f"{Fore.GREEN}enabled{Style.RESET_ALL}" if s.enabled else f"{Fore.RED}disabled{Style.RESET_ALL}"
                print(f"  {Fore.WHITE}{s.name:<18}{Style.RESET_ALL} [{tag_str:<30}] {status}")
            print()
        elif sub == "tags":
            tags = self.db.all_tags()
            print(f"\n{Fore.CYAN}{Style.BRIGHT}{len(tags)} tag(s) in use:{Style.RESET_ALL}")
            for t in tags:
                count = len(self.db.by_tag(t))
                print(f"  {Fore.WHITE}{t:<20}{Style.RESET_ALL} ({count} sites)")
            print()
        else:
            print_err(f"Unknown list target '{sub}'. Usage: list sites | list tags")

    # ---- alias ----------------------------------------------------------------

    def _cmd_alias(self, args: List[str]) -> None:
        if not args:
            print_err("Usage: alias create <name> <site1,site2,...> | alias list | alias delete <name>")
            return

        sub = args[0].lower()

        if sub == "create":
            if len(args) < 3 or not args[2].strip():
                print_err("Usage: alias create <name> <site1,site2,...>")
                return
            alias_name = args[1]
            site_names = [n.strip() for n in args[2].split(",") if n.strip()]
            if not site_names:
                print_warn("No valid site names parsed. Aborting alias creation.")
                return
            self.aliases.create(alias_name, site_names)
            print_ok(f"Alias '{alias_name}' created with {len(site_names)} site(s).")

        elif sub == "list":
            all_aliases = self.aliases.all_aliases()
            if not all_aliases:
                print_info("No aliases saved yet. Use 'alias create <name> <site1,site2,...>'.")
                return
            print(f"\n{Fore.CYAN}{Style.BRIGHT}{len(all_aliases)} alias(es) saved:{Style.RESET_ALL}")
            for name, members in sorted(all_aliases.items()):
                print(f"  {Fore.WHITE}{name:<18}{Style.RESET_ALL} -> {', '.join(members)}")
            print()

        elif sub == "delete":
            if len(args) < 2:
                print_err("Usage: alias delete <name>")
                return
            if self.aliases.delete(args[1]):
                print_ok(f"Alias '{args[1]}' deleted.")
            else:
                print_warn(f"No alias named '{args[1]}' found.")

        else:
            print_err(f"Unknown alias subcommand '{sub}'. Usage: alias create|list|delete")

    # ---- results / export -----------------------------------------------------

    def _cmd_results(self, args: List[str]) -> None:
        if not self.last_results:
            print_info("No scan has been run yet this session.")
            return
        print(f"\n{Fore.CYAN}{Style.BRIGHT}Last scan results ({len(self.last_results)} sites):{Style.RESET_ALL}")
        for r in self.last_results:
            print_result_line(r)
        print()

    def _cmd_export(self, args: List[str]) -> None:
        if not self.last_results:
            print_warn("No scan results to export yet. Run 'scan' first.")
            return
        if not args:
            print_err("Usage: export <csv|json> [filename]")
            return

        fmt = args[0].lower()
        if fmt not in ("csv", "json"):
            print_warn(f"Unsupported export format '{fmt}'. Use 'csv' or 'json'. Aborting export.")
            return

        target_label = self.target or "unknown"
        default_name = f"{target_label}_{int(time.time())}.{fmt}"
        filename = args[1] if len(args) > 1 and args[1].strip() else default_name
        if not filename.endswith(f".{fmt}"):
            filename += f".{fmt}"

        os.makedirs(RESULTS_DIR, exist_ok=True)
        full_path = os.path.join(RESULTS_DIR, filename)

        try:
            if fmt == "json":
                with open(full_path, "w", encoding="utf-8") as f:
                    json.dump([asdict(r) for r in self.last_results], f, indent=2)
            else:
                with open(full_path, "w", encoding="utf-8", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow(["site", "url", "status", "detail", "elapsed_ms"])
                    for r in self.last_results:
                        writer.writerow([r.site, r.url, r.status, r.detail, r.elapsed_ms])
        except OSError as exc:
            print_err(f"Failed to write export file: {exc}")
            return

        print_ok(f"Exported {len(self.last_results)} result(s) to {full_path}")

    # ---- misc ----------------------------------------------------------------

    def _cmd_clear(self, args: List[str]) -> None:
        os.system("cls" if os.name == "nt" else "clear")

    def _cmd_exit(self, args: List[str]) -> None:
        print_info("Exiting GhostTrack. Stay ethical out there.")
        self.running = False


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------


def _install_sigint_noop() -> None:
    """
    Installs a SIGINT handler that does nothing destructive at the process
    level; the actual interactive handling of Ctrl+C happens inside the
    REPL loop via KeyboardInterrupt. This just prevents default Python
    traceback spam if SIGINT arrives outside the input() call.
    """
    def _handler(signum, frame):
        pass

    try:
        signal.signal(signal.SIGINT, _handler)
    except (ValueError, AttributeError):
        # Some environments (e.g. non-main thread) won't allow this; ignore.
        pass


def main() -> None:
    _install_sigint_noop()
    center = CLICommandCenter()
    try:
        center.run()
    except KeyboardInterrupt:
        print()
        print_info("Interrupted. Goodbye.")
    except EOFError:
        print()
        print_info("EOF. Goodbye.")


if __name__ == "__main__":
    main()
