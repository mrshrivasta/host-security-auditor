#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 HOSTSGUARD
 Hosts File Tampering Detector - CLI + Web App
--------------------------------------------------------------------------------
 Author  : Karanam Shrivasta
 GitHub  : https://github.com/mrshrivasta
 LinkedIn: https://www.linkedin.com/in/karanam-shrivasta/
 Version : 1.0.0
--------------------------------------------------------------------------------
 WHY THE HOSTS FILE MATTERS
   It is consulted BEFORE DNS. A line in it silently overrides the entire naming
   system for that name - no lookup, no DNSSEC, no certificate warning until the
   connection is already being made somewhere else. That makes it the cheapest
   possible way to redirect a machine, and malware has used it for decades to
   point antivirus update servers at nowhere and banking sites at somewhere.

 THE DISTINCTION THIS TOOL IS BUILT AROUND
   *** BLOCKING IS ORDINARY. REDIRECTING IS NOT. ***
   Millions of people run ad-blocking hosts files with hundreds of thousands of
   entries pointing at 0.0.0.0. That is deliberate, benign, and it would drown
   any tool that treated every unusual entry as an attack.

     BLOCK     name -> 0.0.0.0, 127.0.0.1 or ::  - the name goes nowhere.
               Ordinary. The question is only WHICH names.
     REDIRECT  name -> a real, routable address  - traffic goes THERE instead.
               Rare in normal use, and the shape of an attack.

   So a 200,000-line ad blocker produces one calm informational finding, while a
   single line pointing a bank at a public address is reported as critical.

 WHAT IT LOOKS FOR
   - Well-known names redirected to routable addresses, weighted by what the name
     is: banks and payment providers, security vendors and OS update services,
     package registries, and major platforms.
   - Security and update services BLOCKED, which is how malware stops a machine
     from ever getting a fix.
   - Names that are visually confusable with real ones: mixed scripts, punycode,
     and characters that render identically to Latin letters.
   - Entries hidden by whitespace tricks, unusual line endings, or a name that a
   -   parser reads differently from a human.
   - Duplicates and shadowed lines, where the entry you can see is not the one
     that wins.
   - The file's own permissions, because a world-writable hosts file is the
     problem before anything in it is.
   - Changes since the last run, against a stored fingerprint.

 WHAT IT CANNOT TELL YOU
   - Whether an entry is legitimate. A developer pointing a staging name at a
     server is indistinguishable from an attacker doing the same thing. Only you
     know which entries you put there - so approve them, and the tool goes quiet.
   - Anything about DNS itself. A machine can be redirected just as effectively
     by a poisoned resolver or a rogue DHCP server, and none of that appears
     here.
   - Anything that happened before the first run. The first check becomes the
     baseline; changes are measured from there.

 READ-ONLY
   It reads the hosts file and never writes to it. There is no command here that
   edits, cleans or restores it, deliberately: a tool that repairs a hosts file
   automatically is a tool that can break name resolution on a machine you are
   trying to diagnose.

 LEGAL DISCLAIMER
   Provided "as is" with no warranty. Inspect only machines you own or are
   authorised to inspect. The author accepts no liability for any loss or damage.
================================================================================
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import html as _html
import io
import ipaddress
import json
import math
import os
import platform
import re
import shutil
import sqlite3
import stat
import sys
import textwrap
import time
import unicodedata
from datetime import datetime, timezone

APP_NAME = "HostsGuard"
APP_SHORT = "HOSTSGUARD"
VERSION = "1.0.0"
AUTHOR = "Karanam Shrivasta"
GITHUB = "https://github.com/mrshrivasta"
LINKEDIN = "https://www.linkedin.com/in/karanam-shrivasta/"
DEFAULT_DB = os.environ.get("HOSTSGUARD_DB", "hostsguard.db")

BLOCK_NOT_TAMPER = (
    "Blocking is ordinary; redirecting is not. Ad-blocking hosts files point hundreds of "
    "thousands of names at 0.0.0.0 deliberately. A name sent to a real, routable address is "
    "the shape that matters - that is traffic going somewhere, not nowhere."
)
DISCLAIMER_SHORT = (
    "Read-only: it never edits the hosts file. Blocking is ordinary and reported calmly; "
    "redirecting a name to a routable address is what it flags. It cannot tell a legitimate "
    "entry from a hostile one - approve yours and it goes quiet."
)
DISCLAIMER_LONG = textwrap.dedent(
    """\
    READ-ONLY. This reads the hosts file and never writes to it. There is deliberately no
    command that edits, cleans or restores it: a tool that repairs a hosts file automatically
    is one that can break name resolution on a machine you are trying to diagnose.

    BLOCKING IS ORDINARY, REDIRECTING IS NOT. Millions of machines run ad-blocking hosts
    files with enormous numbers of entries pointing at 0.0.0.0. Treating those as tampering
    would bury the one line that matters. A name pointed at a real, routable address is the
    shape worth attention.

    IT CANNOT TELL A LEGITIMATE ENTRY FROM A HOSTILE ONE. A developer pointing a staging name
    at a server looks exactly like an attacker doing the same. Only you know which entries
    you put there; approve them and later checks stay quiet about them.

    IT SEES ONLY THIS FILE. A machine can be redirected just as effectively by a poisoned
    resolver, a rogue DHCP server or a proxy configuration, and none of that appears here. A
    clean hosts file is not a clean machine.

    IT ONLY SEES CHANGES SINCE IT STARTED RUNNING. The first check becomes the baseline, so
    anything altered before then is recorded as normal.

    Provided "as is" with no warranty; the author accepts no liability for any loss or
    damage."""
)

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_WEIGHT = {"critical": 40.0, "high": 20.0, "medium": 8.0, "low": 3.0, "info": 0.0}
SEV_COLOR = {"critical": "#e5484d", "high": "#f76808", "medium": "#ffb224",
             "low": "#3e9dd8", "info": "#8b8f9b"}
CHANGE_COLOR = {"added": "#e5484d", "removed": "#ffb224", "changed": "#f76808",
                "unchanged": "#3a3f4a"}


def exposure_band(score: float) -> tuple[str, str]:
    if score >= 40:
        return "investigate now", "#e5484d"
    if score >= 20:
        return "worth checking", "#f76808"
    if score >= 8:
        return "minor notes", "#ffb224"
    if score > 0:
        return "nothing alarming", "#3e9dd8"
    return "nothing found", "#30a46c"


HOSTS_PATHS = {
    "linux": ["/etc/hosts"],
    "darwin": ["/etc/hosts", "/private/etc/hosts"],
    "win32": [r"C:\Windows\System32\drivers\etc\hosts",
              r"C:\WINNT\system32\drivers\etc\hosts"],
}


def default_hosts_path() -> str:
    for p in HOSTS_PATHS.get(sys.platform, ["/etc/hosts"]):
        if os.path.exists(p):
            return p
    return HOSTS_PATHS.get(sys.platform, ["/etc/hosts"])[0]


# =============================================================================
# SECTION 1 - Utilities
# =============================================================================

def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def ts_pretty(iso: str | None) -> str:
    if not iso:
        return "-"
    try:
        return datetime.fromisoformat(iso).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return iso


def clamp(v, lo, hi):
    return max(lo, min(hi, v))


def html_escape(s) -> str:
    return _html.escape("" if s is None else str(s), quote=True)


def fmt_bytes(n) -> str:
    if n is None:
        return "-"
    n = float(n)
    for unit in ("B", "KiB", "MiB"):
        if n < 1024 or unit == "MiB":
            return f"{n:.{0 if unit == 'B' else 1}f} {unit}"
        n /= 1024.0
    return f"{n:.1f} MiB"


def ago(iso: str | None) -> str:
    if not iso:
        return "never"
    try:
        d = (datetime.now(timezone.utc) - datetime.fromisoformat(iso)).total_seconds()
    except Exception:
        return "-"
    if d < 0:
        return "in the future"
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if d >= size:
            return f"{int(d // size)}{unit} ago"
    return f"{int(d)}s ago"


def shorten(s, n=90) -> str:
    s = " ".join(str(s or "").split())
    return s if len(s) <= n else s[:n - 1] + "\u2026"


def F(category, title, severity, description, evidence="", advice=""):
    return {"category": category, "title": title, "severity": severity,
            "description": description, "evidence": str(evidence)[:3000],
            "advice": advice}


# =============================================================================
# SECTION 2 - Names worth caring about
#   Weighted by consequence: redirecting a bank is worse than redirecting a news
#   site, and BLOCKING a security vendor is its own kind of attack.
# =============================================================================

SENSITIVE = {
    "security": (
        "security and antivirus vendors - blocking these is how malware stops a machine "
        "from ever getting a fix",
        ("virustotal.com", "malwarebytes.com", "kaspersky.com", "avast.com", "avg.com",
         "bitdefender.com", "eset.com", "sophos.com", "trendmicro.com", "mcafee.com",
         "norton.com", "symantec.com", "clamav.net", "crowdstrike.com", "sentinelone.com",
         "f-secure.com", "drweb.com", "comodo.com", "webroot.com", "emsisoft.com",
         "safebrowsing.googleapis.com", "sb-ssl.google.com", "urlhaus.abuse.ch")),
    "updates": (
        "operating system and software update services - blocking these leaves a machine "
        "unpatched",
        ("windowsupdate.com", "update.microsoft.com", "sls.microsoft.com",
         "swcdn.apple.com", "swscan.apple.com", "gs.apple.com", "mesu.apple.com",
         "archive.ubuntu.com", "security.ubuntu.com", "deb.debian.org",
         "security.debian.org", "mirrors.fedoraproject.org", "dl.fedoraproject.org",
         "packages.microsoft.com", "download.windowsupdate.com")),
    "banking": (
        "banks and payment providers - the classic target for redirection",
        ("paypal.com", "stripe.com", "chase.com", "wellsfargo.com", "bankofamerica.com",
         "citi.com", "citibank.com", "hsbc.com", "barclays.co.uk", "lloydsbank.com",
         "santander.com", "revolut.com", "wise.com", "coinbase.com", "binance.com",
         "sbi.co.in", "icicibank.com", "hdfcbank.com", "axisbank.com", "onlinesbi.sbi",
         "americanexpress.com", "discover.com", "capitalone.com")),
    "identity": (
        "identity providers and account services - a redirect here harvests credentials for "
        "everything else",
        ("accounts.google.com", "login.microsoftonline.com", "login.live.com",
         "appleid.apple.com", "okta.com", "auth0.com", "duosecurity.com",
         "login.yahoo.com", "id.atlassian.com")),
    "packages": (
        "package registries - a redirect here can substitute the code you install",
        ("pypi.org", "files.pythonhosted.org", "registry.npmjs.org", "npmjs.com",
         "rubygems.org", "crates.io", "static.crates.io", "repo.maven.apache.org",
         "packagist.org", "nuget.org", "hub.docker.com", "registry-1.docker.io",
         "github.com", "raw.githubusercontent.com", "codeload.github.com",
         "gitlab.com", "bitbucket.org")),
    "platforms": (
        "major platforms and communications services",
        ("google.com", "gmail.com", "youtube.com", "facebook.com", "instagram.com",
         "whatsapp.com", "signal.org", "telegram.org", "x.com", "twitter.com",
         "linkedin.com", "amazon.com", "apple.com", "microsoft.com", "office.com",
         "outlook.com", "dropbox.com", "slack.com", "zoom.us", "cloudflare.com")),
}
CATEGORY_SEVERITY_REDIRECT = {"banking": "critical", "identity": "critical",
                              "security": "critical", "packages": "critical",
                              "updates": "high", "platforms": "high"}
CATEGORY_SEVERITY_BLOCK = {"security": "high", "updates": "high", "banking": "medium",
                           "identity": "medium", "packages": "medium",
                           "platforms": "info"}

_SENSITIVE_INDEX: dict[str, str] = {}
for _cat, (_why, _names) in SENSITIVE.items():
    for _n in _names:
        _SENSITIVE_INDEX[_n] = _cat


def sensitive_category(name: str) -> tuple[str | None, str]:
    """Which sensitive group a name belongs to, matching parent domains too."""
    n = (name or "").lower().rstrip(".")
    if n in _SENSITIVE_INDEX:
        cat = _SENSITIVE_INDEX[n]
        return cat, SENSITIVE[cat][0]
    parts = n.split(".")
    for i in range(1, len(parts) - 1):
        parent = ".".join(parts[i:])
        if parent in _SENSITIVE_INDEX:
            cat = _SENSITIVE_INDEX[parent]
            return cat, SENSITIVE[cat][0]
    return None, ""


# Characters that render like Latin letters but are not. A name mixing scripts is
# how a hosts entry is made to look like one thing and resolve as another.
CONFUSABLE_SCRIPTS = ("CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE", "FULLWIDTH")


def script_analysis(name: str) -> dict:
    """Is this name written in more than one script, or in punycode?"""
    out = {"ascii": True, "punycode": False, "scripts": [], "mixed": False,
           "confusable": False, "decoded": None, "suspicious_chars": []}
    if not name:
        return out
    out["ascii"] = all(ord(c) < 128 for c in name)
    labels = name.lower().split(".")
    if any(l.startswith("xn--") for l in labels):
        out["punycode"] = True
        try:
            out["decoded"] = name.encode("ascii").decode("idna")
        except Exception:
            out["decoded"] = None
    target = out["decoded"] or name
    scripts = set()
    for ch in target:
        if not ch.isalpha():
            continue
        try:
            script = unicodedata.name(ch).split()[0]
        except ValueError:
            continue
        scripts.add(script)
        if script in CONFUSABLE_SCRIPTS:
            out["suspicious_chars"].append(
                f"{ch!r} ({unicodedata.name(ch, 'unnamed')})")
    out["scripts"] = sorted(scripts)
    out["mixed"] = len(scripts) > 1
    out["confusable"] = bool(out["suspicious_chars"])
    return out


# =============================================================================
# SECTION 3 - Reading and parsing
# =============================================================================

BLOCK_ADDRESSES = {"0.0.0.0", "127.0.0.1", "::", "::1", "0000:0000:0000:0000:0000:0000:0000:0000"}


def classify_address(addr: str) -> dict:
    """Does this entry send a name nowhere, or somewhere?"""
    out = {"address": addr, "valid": False, "kind": "unknown", "routable": False,
           "blocks": False, "scope": ""}
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        out["kind"] = "not an address"
        return out
    out["valid"] = True
    if addr in BLOCK_ADDRESSES or ip.is_unspecified or ip.is_loopback:
        out.update(kind="block", blocks=True,
                   scope="loopback" if ip.is_loopback else "unspecified")
        return out
    # Python lumps the RFC 5737 documentation ranges in with private space. They
    # are neither: nothing routes them, so an entry pointing at one goes nowhere
    # in practice, and saying "private" would be misleading.
    if any(ip in ipaddress.ip_network(n) for n in
           ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")):
        out.update(kind="redirect", routable=False, scope="documentation (RFC 5737)")
    elif ip in ipaddress.ip_network("198.18.0.0/15"):
        out.update(kind="redirect", routable=False, scope="benchmarking (RFC 2544)")
    elif ip.is_private:
        out.update(kind="redirect", routable=True, scope="private")
    elif ip.is_link_local:
        out.update(kind="redirect", routable=False, scope="link-local")
    elif ip.is_multicast:
        out.update(kind="unusual", scope="multicast")
    elif ip.is_reserved:
        out.update(kind="unusual", scope="reserved")
    else:
        out.update(kind="redirect", routable=True, scope="public")
    return out


def read_hosts(path: str | None = None) -> dict:
    """Read the file, its metadata and its permissions. Never writes."""
    path = path or default_hosts_path()
    out = {"path": os.path.abspath(path), "text": None, "error": None, "size": None,
           "sha256": None, "mtime": None, "mode": None, "owner": None,
           "world_writable": False, "group_writable": False, "line_endings": None,
           "encoding": None, "has_bom": False}
    try:
        st = os.stat(path)
    except OSError as e:
        out["error"] = f"{path}: {e}"
        return out
    out["size"] = st.st_size
    out["mtime"] = datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat()
    out["mode"] = stat.filemode(st.st_mode)
    out["world_writable"] = bool(st.st_mode & stat.S_IWOTH)
    out["group_writable"] = bool(st.st_mode & stat.S_IWGRP)
    try:
        import pwd
        out["owner"] = pwd.getpwuid(st.st_uid).pw_name
    except Exception:
        out["owner"] = str(st.st_uid)
    try:
        with open(path, "rb") as fh:
            raw = fh.read(16 * 1024 * 1024)
    except OSError as e:
        out["error"] = f"could not read {path}: {e}"
        return out
    out["sha256"] = hashlib.sha256(raw).hexdigest()
    if raw.startswith(b"\xef\xbb\xbf"):
        out["has_bom"] = True
        raw = raw[3:]
    for enc in ("utf-8", "utf-16", "latin-1"):
        try:
            out["text"] = raw.decode(enc)
            out["encoding"] = enc
            break
        except UnicodeDecodeError:
            continue
    if out["text"] is None:
        out["error"] = "the file could not be decoded in any expected encoding"
        return out
    if "\r\n" in out["text"]:
        out["line_endings"] = "CRLF"
    elif "\r" in out["text"]:
        out["line_endings"] = "CR"
    elif "\n" in out["text"]:
        out["line_endings"] = "LF"
    return out


def parse_hosts(text: str) -> dict:
    """Parse into entries, keeping every oddity a human would miss."""
    out = {"entries": [], "comments": 0, "blank": 0, "malformed": [], "total_lines": 0}
    seen_names: dict[str, dict] = {}
    for lineno, raw in enumerate(text.splitlines(), 1):
        out["total_lines"] += 1
        stripped = raw.strip()
        if not stripped:
            out["blank"] += 1
            continue
        if stripped.startswith("#"):
            out["comments"] += 1
            continue
        # a comment can begin mid-line; everything after it is inert
        code, _, trailing = raw.partition("#")
        parts = code.split()
        if len(parts) < 2:
            out["malformed"].append({
                "line": lineno, "text": shorten(raw, 160),
                "why": ("an address with no name - the line does nothing"
                        if len(parts) == 1 else "the line has no usable content")})
            continue
        addr, names = parts[0], parts[1:]
        info = classify_address(addr)
        if not info["valid"]:
            out["malformed"].append({
                "line": lineno, "text": shorten(raw, 160),
                "why": f"'{addr}' is not an IP address, so the whole line is ignored by "
                       f"the resolver"})
            continue
        for position, name in enumerate(names):
            clean = name.rstrip(".").lower()
            script = script_analysis(name)
            cat, cat_why = sensitive_category(clean)
            entry = {
                "line": lineno, "address": addr, "name": name, "normalised": clean,
                "position": position, "aliases": [n for n in names if n != name],
                "kind": info["kind"], "blocks": info["blocks"],
                "routable": info["routable"], "scope": info["scope"],
                "category": cat, "category_why": cat_why,
                "comment": trailing.strip() or None,
                "raw": shorten(raw, 300),
                "has_tab": "\t" in raw,
                "trailing_space": raw != raw.rstrip(),
                "ascii": script["ascii"], "punycode": script["punycode"],
                "mixed_script": script["mixed"], "confusable": script["confusable"],
                "decoded": script["decoded"], "scripts": script["scripts"],
                "suspicious_chars": script["suspicious_chars"],
                "shadowed_by": None,
            }
            # first entry for a name wins; later ones are dead configuration
            prior = seen_names.get(clean)
            if prior is None:
                seen_names[clean] = entry
            else:
                entry["shadowed_by"] = prior["line"]
            out["entries"].append(entry)
    out["unique_names"] = len(seen_names)
    return out


# =============================================================================
# SECTION 4 - Findings
# =============================================================================

# Above this many entries the file is obviously a blocklist, and the report says
# so once rather than complaining line by line.
BLOCKLIST_THRESHOLD = 500


def analyse(meta: dict, parsed: dict, approved: dict) -> list[dict]:
    out: list[dict] = []
    if meta.get("error"):
        return [F("File", "The hosts file could not be read", "info", meta["error"], "",
                  "Nothing below was checked. An empty result means 'not checked', not "
                  "'clean'.")]

    entries = parsed["entries"]
    blocks = [e for e in entries if e["blocks"]]
    redirects = [e for e in entries if e["kind"] == "redirect"]
    unusual = [e for e in entries if e["kind"] == "unusual"]
    approved_keys = set(approved)

    def key(e):
        return f"{e['address']} {e['normalised']}"

    # ---- permissions come first: they are the problem before the contents ----
    if meta["world_writable"]:
        out.append(F("Permissions", "The hosts file is world-writable", "critical",
                     f"Mode {meta['mode']} - any user on this machine can rewrite it.",
                     f"{meta['path']}  owner {meta['owner']}",
                     "Fix this before anything else in this report: whatever the file says "
                     "today, anyone can change it. On Unix: chmod 644 and chown root."))
    elif meta["group_writable"]:
        out.append(F("Permissions", "The hosts file is group-writable", "medium",
                     f"Mode {meta['mode']} - members of the owning group can rewrite it.",
                     f"{meta['path']}  owner {meta['owner']}",
                     "Usually unintended. 644 is the normal mode."))

    # ---- the headline distinction ----
    unapproved_redirects = [e for e in redirects if key(e) not in approved_keys]
    for e in sorted(unapproved_redirects,
                    key=lambda x: (x["category"] is None, x["category"] or "")):
        cat = e["category"]
        if cat:
            sev = CATEGORY_SEVERITY_REDIRECT.get(cat, "high")
            out.append(F("Redirect", f"{e['normalised']} is redirected to {e['address']}",
                         sev,
                         f"This is one of the {e['category_why']}. The name will resolve to "
                         f"{e['address']} on this machine, whatever DNS says.",
                         f"line {e['line']}: {e['raw']}"
                         + (f"\naddress scope: {e['scope']}" if e["scope"] else ""),
                         "Nothing about the connection will warn you: there is no lookup to "
                         "fail and no certificate check until the connection is already "
                         "being made. If you did not add this line, treat the machine as "
                         "compromised. If you did, approve it and this goes quiet."))
    generic = [e for e in unapproved_redirects if not e["category"]]
    if generic:
        public = [e for e in generic if e["scope"] == "public"]
        out.append(F("Redirect", f"{len(generic)} name(s) redirected to a routable address",
                     "medium" if public else "low",
                     "These names resolve to a real address rather than being blocked.",
                     "\n".join(f"line {e['line']}: {e['address']}  {e['normalised']}"
                               + (f"  [{e['scope']}]" if e["scope"] else "")
                               for e in generic[:12]),
                     f"{len(public)} of them point at a PUBLIC address, which is unusual "
                     f"outside a deliberate override; a private address is the ordinary "
                     f"shape for local development. Approve the ones you added."
                     if public else
                     "Private addresses here are the ordinary shape for local development "
                     "and staging. Approve the ones you added."))

    # ---- blocked names, weighted by what they are ----
    if len(blocks) >= BLOCKLIST_THRESHOLD:
        out.append(F("Blocklist", f"{len(blocks):,} names are blocked", "info",
                     "A file this size is an ad-blocking or tracker-blocking list.",
                     f"{parsed['unique_names']:,} unique name(s) across "
                     f"{parsed['total_lines']:,} line(s)",
                     "Entirely ordinary and reported once rather than line by line. "
                     "Blocking sends a name nowhere; it is redirection that moves traffic "
                     "somewhere."))
    blocked_sensitive: dict[str, list] = {}
    for e in blocks:
        if e["category"] and key(e) not in approved_keys:
            blocked_sensitive.setdefault(e["category"], []).append(e)
    for cat, items in blocked_sensitive.items():
        sev = CATEGORY_SEVERITY_BLOCK.get(cat, "low")
        if cat == "platforms" and len(blocks) >= BLOCKLIST_THRESHOLD:
            continue                # a blocklist blocking platforms is the point of it
        out.append(F("Blocked", f"{len(items)} {cat} name(s) are blocked", sev,
                     f"These are {SENSITIVE[cat][0]}.",
                     "\n".join(f"line {e['line']}: {e['address']}  {e['normalised']}"
                               for e in items[:10]),
                     "Malware blocks security and update services so a machine can never "
                     "download a fix - it is one of the oldest tricks there is. It is also "
                     "what a privacy-focused blocklist does on purpose. Check whether you "
                     "chose this."
                     if cat in ("security", "updates") else
                     "Blocking sends these nowhere rather than somewhere, so this is far "
                     "less serious than a redirect. Worth knowing it is there."))

    # ---- names designed to be misread ----
    confusable = [e for e in entries if e["confusable"] or e["mixed_script"]]
    for e in confusable[:10]:
        out.append(F("Deception", f"'{e['name']}' is not written in plain Latin script",
                     "critical" if e["kind"] == "redirect" else "high",
                     f"The name mixes scripts ({', '.join(e['scripts'])}) or uses "
                     f"characters that look like Latin letters but are not."
                     + (f" It decodes to '{e['decoded']}'." if e["decoded"] else ""),
                     f"line {e['line']}: {e['raw']}\n"
                     + "\n".join(e["suspicious_chars"][:6]),
                     "This is how an entry is made to look like a name you trust while "
                     "resolving as something else - it can be visually identical in the "
                     "file. Read the character list above, not the rendered name."))
    puny = [e for e in entries if e["punycode"] and not e["confusable"]]
    if puny:
        out.append(F("Deception", f"{len(puny)} punycode name(s)", "low",
                     "These are internationalised names encoded as ASCII.",
                     "\n".join(f"line {e['line']}: {e['name']}"
                               + (f"  decodes to {e['decoded']}" if e["decoded"] else "")
                               for e in puny[:8]),
                     "Legitimate for genuinely non-Latin domains. Check that the decoded "
                     "form is what you expect."))

    # ---- entries that do not do what they look like ----
    shadowed = [e for e in entries if e["shadowed_by"]]
    if shadowed:
        conflicting = [e for e in shadowed
                       if any(o["normalised"] == e["normalised"]
                              and o["address"] != e["address"]
                              and o["line"] == e["shadowed_by"] for o in entries)]
        out.append(F("Structure", f"{len(shadowed)} entry(ies) are shadowed by an earlier "
                     f"line", "medium" if conflicting else "low",
                     "The resolver uses the FIRST match for a name; these come later and "
                     "never take effect.",
                     "\n".join(f"line {e['line']} ({e['address']} {e['normalised']}) is "
                               f"overridden by line {e['shadowed_by']}"
                               for e in shadowed[:10]),
                     f"{len(conflicting)} of them point somewhere DIFFERENT from the line "
                     f"that wins, so the entry you can see is not the one in effect - a "
                     f"neat way to hide a change in plain sight. Read the first match, not "
                     f"the last." if conflicting else
                     "Duplicates of the same address are harmless clutter."))
    for e in [x for x in entries if x["trailing_space"] or x["has_tab"]][:1]:
        odd = [x for x in entries if x["trailing_space"] or x["has_tab"]]
        out.append(F("Structure", f"{len(odd)} line(s) use tabs or trailing whitespace",
                     "low", "Whitespace that a reader will not see.",
                     "\n".join(f"line {x['line']}: {x['raw']!r}" for x in odd[:6]),
                     "Harmless by itself - tabs are perfectly valid separators - but it is "
                     "also how a line is made to look different from what it is. Worth a "
                     "glance at the raw bytes above."))
    if parsed["malformed"]:
        out.append(F("Structure", f"{len(parsed['malformed'])} line(s) are not valid "
                     f"entries", "low",
                     "These are ignored by the resolver entirely.",
                     "\n".join(f"line {x['line']}: {x['why']}\n  {x['text']}"
                               for x in parsed["malformed"][:6]),
                     "Usually a typo or an edit gone wrong. A line the resolver ignores is "
                     "also a line that can hide content from a casual reader."))
    if unusual:
        out.append(F("Structure", f"{len(unusual)} entry(ies) point at an unusual address",
                     "medium",
                     "Multicast or reserved addresses in a hosts file do nothing useful.",
                     "\n".join(f"line {e['line']}: {e['address']}  {e['normalised']} "
                               f"[{e['scope']}]" for e in unusual[:8]),
                     "These will not connect anywhere. Their presence is odd enough to be "
                     "worth explaining."))
    if meta["has_bom"]:
        out.append(F("Structure", "The file starts with a byte order mark", "low",
                     "A UTF-8 BOM precedes the first line.", "",
                     "Some resolvers read the first entry as containing an invisible "
                     "character and skip it, which silently changes behaviour. It usually "
                     "means the file was edited in a Windows editor."))
    if meta["line_endings"] == "CR":
        out.append(F("Structure", "The file uses classic Mac line endings", "medium",
                     "Lines end with CR alone, which most resolvers do not split on.",
                     "", "The whole file may be read as a single line and ignored."))

    # ---- what is normal ----
    localhost = [e for e in entries if e["normalised"] in ("localhost", "localhost.localdomain")]
    if not localhost:
        out.append(F("Structure", "There is no localhost entry", "low",
                     "The file does not map localhost.", "",
                     "Unusual - most systems expect it, and some software fails oddly "
                     "without it. Not dangerous, just worth noticing."))

    approved_hits = [e for e in entries if key(e) in approved_keys]
    if approved_hits:
        out.append(F("Baseline", f"{len(approved_hits)} entry(ies) are approved", "info",
                     "You have marked these as expected, so they are not reported above.",
                     "\n".join(f"{e['address']}  {e['normalised']}"
                               for e in approved_hits[:10]),
                     "Approval is by address and name together, so if either changes the "
                     "entry is reported again."))

    out.append(F("Summary", f"{len(entries)} entry(ies), {len(blocks)} blocked, "
                 f"{len(redirects)} redirected", "info",
                 f"{parsed['unique_names']} unique name(s), {parsed['comments']} comment "
                 f"line(s), {fmt_bytes(meta['size'])}.",
                 f"{meta['path']}\nsha256 {meta['sha256']}\n"
                 f"modified {meta['mtime'][:19].replace('T', ' ')} UTC, mode {meta['mode']}",
                 BLOCK_NOT_TAMPER + " This file is only one way a machine can be "
                 "redirected - a poisoned resolver or rogue DHCP server does the same job "
                 "and appears nowhere here."))
    return out


def risk_score(findings: list[dict]) -> float:
    return round(clamp(sum(SEV_WEIGHT[f["severity"]] for f in findings), 0, 100), 1)


def diff_entries(previous: list[dict], current: list[dict]) -> list[dict]:
    """What changed between two readings, keyed by address and name together."""
    def key(e):
        return f"{e['address']} {e['normalised']}"
    prev = {key(e): e for e in previous}
    cur = {key(e): e for e in current}
    changes = []
    for k in sorted(cur.keys() - prev.keys()):
        e = cur[k]
        changes.append({"kind": "added", "address": e["address"], "name": e["normalised"],
                        "line": e["line"], "entry_kind": e["kind"],
                        "category": e["category"],
                        "detail": f"{e['address']}  {e['normalised']}"})
    for k in sorted(prev.keys() - cur.keys()):
        e = prev[k]
        changes.append({"kind": "removed", "address": e["address"],
                        "name": e["normalised"], "line": e.get("line"),
                        "entry_kind": e.get("kind"), "category": e.get("category"),
                        "detail": f"{e['address']}  {e['normalised']}"})
    # a name whose address moved shows up as both; pair them for clarity
    by_name_prev = {e["normalised"]: e for e in previous}
    for e in current:
        old = by_name_prev.get(e["normalised"])
        if old and old["address"] != e["address"]:
            changes = [c for c in changes
                       if not (c["name"] == e["normalised"]
                               and c["kind"] in ("added", "removed"))]
            changes.append({"kind": "changed", "address": e["address"],
                            "name": e["normalised"], "line": e["line"],
                            "entry_kind": e["kind"], "category": e["category"],
                            "previous_address": old["address"],
                            "detail": f"{e['normalised']}: {old['address']} -> "
                                      f"{e['address']}"})
    return changes


def analyse_changes(changes: list[dict], approved: dict) -> list[dict]:
    out = []
    if not changes:
        return out
    added_redirects = [c for c in changes
                       if c["kind"] in ("added", "changed") and c["entry_kind"] == "redirect"
                       and f"{c['address']} {c['name']}" not in approved]
    for c in added_redirects:
        sev = CATEGORY_SEVERITY_REDIRECT.get(c["category"], "high") if c["category"] \
            else "medium"
        out.append(F("Change", f"A redirect was {c['kind']}: {c['name']}", sev,
                     c["detail"] + (f" (was {c['previous_address']})"
                                    if c.get("previous_address") else ""),
                     f"line {c['line']}",
                     "This entry was not here at the last check. If you did not add it, "
                     "find out who did - and note that the hosts file is usually only "
                     "writable by an administrator, so whatever made this change had that "
                     "level of access."))
    added_blocks = [c for c in changes if c["kind"] == "added"
                    and c["entry_kind"] != "redirect"]
    if added_blocks:
        sensitive = [c for c in added_blocks
                     if c["category"] in ("security", "updates")]
        out.append(F("Change", f"{len(added_blocks)} blocking entry(ies) were added",
                     "high" if sensitive else "info",
                     "New entries that send names nowhere.",
                     "\n".join(c["detail"] for c in added_blocks[:10]),
                     f"{len(sensitive)} of them block security or update services, which "
                     f"is how malware keeps a machine from getting fixed."
                     if sensitive else
                     "Adding blocks is what installing or updating an ad-blocking list "
                     "looks like."))
    removed = [c for c in changes if c["kind"] == "removed"]
    if removed:
        out.append(F("Change", f"{len(removed)} entry(ies) were removed", "info",
                     "Present at the last check and gone now.",
                     "\n".join(c["detail"] for c in removed[:10]),
                     "Ordinary when a blocklist is updated or an override is cleaned up."))
    return out


# =============================================================================
# SECTION 5 - Database
# =============================================================================

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL, hostname TEXT, path TEXT, sha256 TEXT, size INTEGER,
    mtime TEXT, mode TEXT, owner TEXT, world_writable INTEGER DEFAULT 0,
    entries INTEGER DEFAULT 0, blocks INTEGER DEFAULT 0, redirects INTEGER DEFAULT 0,
    unique_names INTEGER DEFAULT 0, changes INTEGER DEFAULT 0, score REAL DEFAULT 0,
    band TEXT, prev_scan_id INTEGER, elapsed_ms INTEGER, error TEXT,
    critical INTEGER DEFAULT 0, high INTEGER DEFAULT 0, medium INTEGER DEFAULT 0,
    low INTEGER DEFAULT 0, info INTEGER DEFAULT 0, note TEXT
);
CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL,
    line INTEGER, address TEXT, name TEXT, kind TEXT, category TEXT,
    scope TEXT, shadowed_by INTEGER, confusable INTEGER DEFAULT 0, raw TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE TABLE IF NOT EXISTS changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL, ts TEXT,
    kind TEXT, address TEXT, name TEXT, previous_address TEXT, entry_kind TEXT,
    category TEXT, detail TEXT, FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL,
    category TEXT, title TEXT, severity TEXT, description TEXT, evidence TEXT,
    advice TEXT, FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE TABLE IF NOT EXISTS approved (
    key TEXT PRIMARY KEY, address TEXT, name TEXT, approved_at TEXT, note TEXT
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL, level TEXT NOT NULL, source TEXT, message TEXT, scan_id INTEGER
);
CREATE INDEX IF NOT EXISTS idx_obs_scan ON observations(scan_id);
CREATE INDEX IF NOT EXISTS idx_chg_scan ON changes(scan_id);
CREATE INDEX IF NOT EXISTS idx_find_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
"""

_DB_PATH = DEFAULT_DB


def set_db_path(p: str) -> None:
    global _DB_PATH
    _DB_PATH = p


def db_path() -> str:
    return _DB_PATH


def connect(path: str | None = None) -> sqlite3.Connection:
    conn = sqlite3.connect(path or _DB_PATH, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(conn=None) -> None:
    own = conn is None
    conn = conn or connect()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        if own:
            conn.close()


def q(sql: str, args: tuple = (), conn=None) -> list[sqlite3.Row]:
    own = conn is None
    conn = conn or connect()
    try:
        return conn.execute(sql, args).fetchall()
    finally:
        if own:
            conn.close()


def q1(sql: str, args: tuple = (), conn=None):
    rows = q(sql, args, conn)
    return rows[0] if rows else None


def log_event(level: str, source: str, message: str, scan_id=None, conn=None) -> None:
    own = conn is None
    conn = conn or connect()
    try:
        conn.execute("INSERT INTO audit_log (ts, level, source, message, scan_id) "
                     "VALUES (?,?,?,?,?)",
                     (now_iso(), level.upper(), source,
                      " ".join(str(message).split())[:1000], scan_id))
        conn.commit()
    except Exception:
        pass
    finally:
        if own:
            conn.close()


def approved_map(conn=None) -> dict:
    return {r["key"]: dict(r) for r in q("SELECT * FROM approved", (), conn)}


def approve_entry(address: str, name: str, note: str = "") -> str:
    key = f"{address} {name.lower().rstrip('.')}"
    conn = connect()
    try:
        init_db(conn)
        conn.execute("INSERT INTO approved (key, address, name, approved_at, note) "
                     "VALUES (?,?,?,?,?) ON CONFLICT(key) DO UPDATE SET "
                     "note=COALESCE(NULLIF(?,''), note)",
                     (key, address, name.lower().rstrip("."), now_iso(), note, note))
        conn.commit()
        log_event("INFO", "baseline", f"Approved {key}", None, conn)
        return key
    finally:
        conn.close()


def revoke_entry(address: str, name: str) -> int:
    key = f"{address} {name.lower().rstrip('.')}"
    conn = connect()
    try:
        n = conn.execute("DELETE FROM approved WHERE key=?", (key,)).rowcount
        conn.commit()
        return n
    finally:
        conn.close()


def previous_entries(conn=None) -> tuple[list[dict], int | None]:
    row = q1("SELECT id FROM scans ORDER BY id DESC LIMIT 1", (), conn)
    if not row:
        return [], None
    sid = row["id"]
    out = []
    for r in q("SELECT * FROM observations WHERE scan_id=?", (sid,), conn):
        d = dict(r)
        d["normalised"] = d["name"]
        out.append(d)
    return out, sid


def save_scan(meta: dict, parsed: dict, changes: list, findings: list, prev_id,
              duration_ms: int, note: str = "") -> int:
    conn = connect()
    try:
        init_db(conn)
        counts = {s: 0 for s in SEVERITIES}
        for f in findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        entries = parsed.get("entries", [])
        score = risk_score(findings)
        band, _c = exposure_band(score)
        cur = conn.execute(
            "INSERT INTO scans (ts, hostname, path, sha256, size, mtime, mode, owner,"
            " world_writable, entries, blocks, redirects, unique_names, changes, score,"
            " band, prev_scan_id, elapsed_ms, error, critical, high, medium, low, info,"
            " note) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (now_iso(), platform.node(), meta.get("path"), meta.get("sha256"),
             meta.get("size"), meta.get("mtime"), meta.get("mode"), meta.get("owner"),
             int(bool(meta.get("world_writable"))), len(entries),
             sum(1 for e in entries if e["blocks"]),
             sum(1 for e in entries if e["kind"] == "redirect"),
             parsed.get("unique_names", 0), len(changes), score, band, prev_id,
             duration_ms, meta.get("error"), counts["critical"], counts["high"],
             counts["medium"], counts["low"], counts["info"], note))
        sid = cur.lastrowid
        for e in entries:
            conn.execute(
                "INSERT INTO observations (scan_id, line, address, name, kind, category,"
                " scope, shadowed_by, confusable, raw) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (sid, e["line"], e["address"], e["normalised"], e["kind"], e["category"],
                 e["scope"], e["shadowed_by"], int(bool(e["confusable"])), e["raw"]))
        ts = now_iso()
        for c in changes:
            conn.execute(
                "INSERT INTO changes (scan_id, ts, kind, address, name, previous_address,"
                " entry_kind, category, detail) VALUES (?,?,?,?,?,?,?,?,?)",
                (sid, ts, c["kind"], c.get("address"), c.get("name"),
                 c.get("previous_address"), c.get("entry_kind"), c.get("category"),
                 c.get("detail")))
        for f in findings:
            conn.execute("INSERT INTO findings (scan_id, category, title, severity,"
                         " description, evidence, advice) VALUES (?,?,?,?,?,?,?)",
                         (sid, f["category"], f["title"], f["severity"], f["description"],
                          f["evidence"], f.get("advice", "")))
        conn.commit()
        log_event("INFO", "scan", f"Scan #{sid}: {len(entries)} entry(ies), "
                  f"{len(changes)} change(s), score {score}", sid, conn)
        for c in changes:
            if c["kind"] in ("added", "changed") and c.get("entry_kind") == "redirect":
                log_event("WARN", "change", f"Redirect {c['kind']}: {c['detail']}",
                          sid, conn)
        return sid
    finally:
        conn.close()


def latest_scan_id(conn=None):
    row = q1("SELECT id FROM scans ORDER BY id DESC LIMIT 1", (), conn)
    return row["id"] if row else None


def scan_summary(sid: int, conn=None):
    row = q1("SELECT * FROM scans WHERE id=?", (sid,), conn)
    if not row:
        return None
    d = dict(row)
    d["band_colour"] = exposure_band(d["score"] or 0)[1]
    return d


def run_scan(path: str | None = None, note: str = "") -> tuple:
    t0 = time.time()
    init_db()
    meta = read_hosts(path)
    parsed = {"entries": [], "unique_names": 0, "comments": 0, "blank": 0,
              "malformed": [], "total_lines": 0}
    if meta.get("text") is not None:
        parsed = parse_hosts(meta["text"])
    approved = approved_map()
    previous, prev_id = previous_entries()
    changes = diff_entries(previous, parsed["entries"]) if previous else []
    findings = analyse(meta, parsed, approved) + analyse_changes(changes, approved)
    sid = save_scan(meta, parsed, changes, findings, prev_id,
                    int((time.time() - t0) * 1000), note)
    return sid, meta, parsed, changes, findings


# =============================================================================
# SECTION 6 - Charts (hand-drawn SVG: no CDN, no JS library)
# =============================================================================

def svg_split(parsed: dict, width=430, title="Blocked versus redirected") -> str:
    """The distinction the whole tool turns on, drawn."""
    entries = parsed.get("entries", [])
    if not entries:
        return f'<div class="chart-empty">{html_escape(title)}: no entries</div>'
    blocks = sum(1 for e in entries if e["blocks"])
    redirects = sum(1 for e in entries if e["kind"] == "redirect")
    other = len(entries) - blocks - redirects
    total = len(entries) or 1
    rows = [("blocked - goes nowhere", blocks, "#30a46c"),
            ("redirected - goes somewhere", redirects, "#e5484d"),
            ("other", other, "#8b8f9b")]
    rows = [r for r in rows if r[1]]
    h, gap, pad = 34, 10, 8
    height = pad * 2 + len(rows) * (h + gap)
    bw = width - 20
    parts = []
    for i, (label, n, colour) in enumerate(rows):
        y = pad + i * (h + gap)
        w = max(3.0, bw * n / total)
        parts.append(f'<rect x="10" y="{y}" width="{bw}" height="{h}" rx="5" '
                     f'class="btrack"/>'
                     f'<rect x="10" y="{y}" width="{w:.1f}" height="{h}" rx="5" '
                     f'fill="{colour}"><title>{html_escape(label)}: {n:,}</title></rect>'
                     f'<text x="18" y="{y + 15}" class="bv">{n:,}</text>'
                     f'<text x="18" y="{y + 28}" class="bl">{html_escape(label)}</text>')
    return (f'<figure class="chart"><figcaption>{html_escape(title)} &middot; '
            f'blocking is ordinary, redirecting is not</figcaption>'
            f'<svg viewBox="0 0 {width} {height}" width="{width}" height="{height}" '
            f'role="img" aria-label="{html_escape(title)}">{"".join(parts)}</svg></figure>')


def svg_redirect_map(parsed: dict, approved: dict, width=940,
                     title="Every name that goes somewhere") -> str:
    entries = [e for e in parsed.get("entries", []) if e["kind"] == "redirect"][:24]
    if not entries:
        return (f'<div class="chart-empty">{html_escape(title)}: nothing is redirected - '
                f'every entry sends its name nowhere</div>')
    row_h, gap, pad_t = 30, 6, 22
    height = pad_t + len(entries) * (row_h + gap) + 10
    parts = [f'<text x="14" y="14" class="bl">NAME</text>',
             f'<text x="{width / 2 + 30}" y="14" class="bl">GOES TO</text>']
    for i, e in enumerate(entries):
        y = pad_t + i * (row_h + gap)
        ok = f"{e['address']} {e['normalised']}" in approved
        colour = ("#30a46c" if ok else
                  "#e5484d" if e["category"] in ("banking", "identity", "security",
                                                 "packages") else
                  "#f76808" if e["category"] else
                  "#ffb224" if e["scope"] == "public" else "#8b8f9b")
        parts.append(f'<rect x="8" y="{y}" width="{width - 16}" height="{row_h}" rx="5" '
                     f'fill="#1a1e26" stroke="{colour}"/>')
        parts.append(f'<text x="20" y="{y + 20}" class="nm">'
                     f'{html_escape(e["normalised"][:44])}</text>')
        mid = width / 2
        parts.append(f'<line x1="{mid - 40}" y1="{y + 15}" x2="{mid + 20}" y2="{y + 15}" '
                     f'stroke="{colour}" stroke-width="2"/>'
                     f'<path d="M {mid + 20} {y + 15} L {mid + 12} {y + 11} '
                     f'L {mid + 12} {y + 19} Z" fill="{colour}"/>')
        parts.append(f'<text x="{mid + 30}" y="{y + 20}" class="addr" fill="{colour}">'
                     f'{html_escape(e["address"])}</text>')
        tag = ("approved" if ok else (e["category"] or e["scope"] or ""))
        if tag:
            parts.append(f'<text x="{width - 20}" y="{y + 20}" text-anchor="end" '
                         f'class="bl">{html_escape(tag)}</text>')
    return (f'<figure class="chart wide"><figcaption>{html_escape(title)} &middot; '
            f'red is a sensitive category, green is one you approved</figcaption>'
            f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" '
            f'role="img" aria-label="{html_escape(title)}">{"".join(parts)}</svg></figure>')


def svg_pie(items, size=180, title="Findings by severity", fmt=lambda v: f"{v:g}"):
    items = [(l, float(v), c) for (l, v, c) in items if v and v > 0]
    total = sum(v for _, v, _ in items)
    if total <= 0:
        return f'<div class="chart-empty">{html_escape(title)}: nothing to show</div>'
    cx = cy = size / 2
    r_out, r_in = size / 2 - 10, size / 2 - 42
    parts, legend, angle = [], [], -90.0
    for label, value, color in items:
        sweep = 360.0 * value / total
        if abs(sweep - 360.0) < 1e-9:
            parts.append(f'<circle cx="{cx}" cy="{cy}" r="{(r_out + r_in) / 2:.2f}" '
                         f'fill="none" stroke="{color}" stroke-width="{r_out - r_in:.2f}"/>')
        else:
            a0, a1 = math.radians(angle), math.radians(angle + sweep)
            x0, y0 = cx + r_out * math.cos(a0), cy + r_out * math.sin(a0)
            x1, y1 = cx + r_out * math.cos(a1), cy + r_out * math.sin(a1)
            x2, y2 = cx + r_in * math.cos(a1), cy + r_in * math.sin(a1)
            x3, y3 = cx + r_in * math.cos(a0), cy + r_in * math.sin(a0)
            lg = 1 if sweep > 180 else 0
            parts.append(f'<path d="M {x0:.2f} {y0:.2f} A {r_out:.2f} {r_out:.2f} 0 {lg} 1 '
                         f'{x1:.2f} {y1:.2f} L {x2:.2f} {y2:.2f} A {r_in:.2f} {r_in:.2f} 0 '
                         f'{lg} 0 {x3:.2f} {y3:.2f} Z" fill="{color}">'
                         f'<title>{html_escape(label)}: {html_escape(fmt(value))}</title>'
                         f'</path>')
        angle += sweep
        legend.append(f'<div class="lg"><i style="background:{color}"></i>'
                      f'<span>{html_escape(label)}</span><b>{html_escape(fmt(value))}</b>'
                      f'</div>')
    return (f'<figure class="chart"><figcaption>{html_escape(title)}</figcaption>'
            f'<div class="chart-row"><svg viewBox="0 0 {size} {size}" width="{size}" '
            f'height="{size}" role="img" aria-label="{html_escape(title)}">{"".join(parts)}'
            f'<text x="{cx}" y="{cy + 5}" text-anchor="middle" class="pie-n">'
            f'{html_escape(fmt(total))}</text></svg>'
            f'<div class="legend">{"".join(legend)}</div></div></figure>')


def svg_history(rows: list[dict], width=430, height=150,
                title="Entries over time") -> str:
    pts = [r for r in rows if r.get("entries") is not None]
    if len(pts) < 2:
        return (f'<div class="chart-empty">{html_escape(title)}: needs at least two checks '
                f'({len(pts)} so far)</div>')
    pad = 32
    mx = max(p["entries"] for p in pts) or 1
    step = (width - pad * 2) / max(len(pts) - 1, 1)
    coords = [(pad + i * step,
               height - pad - (height - pad * 2) * clamp(p["entries"] / mx, 0, 1))
              for i, p in enumerate(pts)]
    d = " ".join(f"{'M' if i == 0 else 'L'} {x:.1f} {y:.1f}"
                 for i, (x, y) in enumerate(coords))
    dots = "".join(
        f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3" '
        f'fill="{"#e5484d" if pts[i].get("changes") else "#5b8def"}">'
        f'<title>scan #{pts[i].get("id")}: {pts[i]["entries"]} entry(ies), '
        f'{pts[i].get("changes", 0)} change(s)</title></circle>'
        for i, (x, y) in enumerate(coords))
    return (f'<figure class="chart"><figcaption>{html_escape(title)} &middot; '
            f'red marks a check where something changed</figcaption>'
            f'<svg viewBox="0 0 {width} {height}" width="{width}" height="{height}" '
            f'role="img" aria-label="{html_escape(title)}">'
            f'<path d="{d}" fill="none" stroke="#5b8def" stroke-width="2"/>{dots}'
            f'</svg></figure>')


def svg_bar(items, width=430, title="", color="#5b8def", fmt=lambda v: f"{v:g}",
            colors=None):
    items = [(str(l), float(v or 0)) for l, v in items]
    if not items or all(v <= 0 for _, v in items):
        return f'<div class="chart-empty">{html_escape(title)}: nothing to show</div>'
    row_h, gap, pad_l, pad_t = 22, 7, 150, 8
    height = pad_t * 2 + len(items) * (row_h + gap)
    mx = max(v for _, v in items) or 1
    bw = width - pad_l - 62
    rows = []
    for i, (label, value) in enumerate(items):
        y = pad_t + i * (row_h + gap)
        w = max(2.0, bw * value / mx)
        c = (colors or {}).get(label, color)
        rows.append(
            f'<text x="{pad_l - 9}" y="{y + row_h * 0.7:.1f}" text-anchor="end" class="bl">'
            f'{html_escape(label[:21])}</text>'
            f'<rect x="{pad_l}" y="{y}" width="{bw}" height="{row_h}" rx="4" class="btrack"/>'
            f'<rect x="{pad_l}" y="{y}" width="{w:.1f}" height="{row_h}" rx="4" fill="{c}">'
            f'<title>{html_escape(label)}: {html_escape(fmt(value))}</title></rect>'
            f'<text x="{pad_l + bw + 7:.1f}" y="{y + row_h * 0.7:.1f}" class="bv">'
            f'{html_escape(fmt(value))}</text>')
    return (f'<figure class="chart"><figcaption>{html_escape(title)}</figcaption>'
            f'<svg viewBox="0 0 {width} {height}" width="{width}" height="{height}" '
            f'role="img" aria-label="{html_escape(title)}">{"".join(rows)}</svg></figure>')


# =============================================================================
# SECTION 7 - Exports
# =============================================================================

def report_payload(sid=None, conn=None) -> dict:
    own = conn is None
    conn = conn or connect()
    try:
        sid = sid or latest_scan_id(conn)
        scan = scan_summary(sid, conn) if sid else None
        return {
            "tool": APP_NAME, "version": VERSION, "author": AUTHOR,
            "generated_at": now_iso(), "disclaimer": DISCLAIMER_LONG,
            "blocking_is_ordinary": BLOCK_NOT_TAMPER,
            "read_only": "The hosts file is opened read-only and never modified. There is "
                         "deliberately no command that edits or repairs it.",
            "limitations": [
                "It cannot tell a legitimate entry from a hostile one - a developer's "
                "override and an attacker's look identical. Approve yours.",
                "It sees only this file. A poisoned resolver, a rogue DHCP server or a "
                "proxy configuration redirects a machine just as effectively and appears "
                "nowhere here.",
                "It only sees changes since it started running; the first check becomes the "
                "baseline.",
                "The sensitive-name list is a curated selection, not exhaustive - a name "
                "that is not on it is not thereby safe.",
                "Blocking is reported calmly by design, so a blocklist that blocks "
                "something you needed will not be flagged loudly.",
            ],
            "scan": scan,
            "entries": [dict(r) for r in q(
                "SELECT * FROM observations WHERE scan_id=? ORDER BY line",
                (sid,), conn)] if sid else [],
            "changes": [dict(r) for r in q(
                "SELECT * FROM changes WHERE scan_id=? ORDER BY kind", (sid,), conn)]
            if sid else [],
            "findings": [dict(r) for r in q(
                "SELECT category,title,severity,description,evidence,advice FROM findings "
                "WHERE scan_id=? ORDER BY CASE severity WHEN 'critical' THEN 0 "
                "WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, id",
                (sid,), conn)] if sid else [],
            "approved": [dict(r) for r in q("SELECT * FROM approved ORDER BY key", (), conn)],
            "scans": [dict(r) for r in q("SELECT id,ts,entries,changes,score,band "
                                         "FROM scans ORDER BY id DESC LIMIT 50", (), conn)],
        }
    finally:
        if own:
            conn.close()


def export_json(sid=None) -> str:
    return json.dumps(report_payload(sid), indent=2, default=str)


def export_csv(sid=None) -> str:
    conn = connect()
    try:
        sid = sid or latest_scan_id(conn)
        scan = scan_summary(sid, conn)
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n")
        w.writerow([f"# {APP_NAME} v{VERSION} by {AUTHOR}"])
        w.writerow([f"# scan={sid} generated={now_iso()}"])
        w.writerow([f"# {DISCLAIMER_SHORT}"])
        w.writerow(["# Blocking is ordinary; redirecting is what matters."])
        if not scan:
            return buf.getvalue()
        w.writerow([])
        w.writerow(["## Entries"])
        w.writerow(["line", "address", "name", "kind", "category", "scope",
                    "shadowed_by", "confusable"])
        for r in q("SELECT * FROM observations WHERE scan_id=? ORDER BY line",
                   (sid,), conn):
            w.writerow([r["line"], r["address"], r["name"], r["kind"], r["category"],
                        r["scope"], r["shadowed_by"], r["confusable"]])
        w.writerow([])
        w.writerow(["## Changes"])
        w.writerow(["kind", "address", "name", "previous_address", "detail"])
        for r in q("SELECT * FROM changes WHERE scan_id=? ORDER BY kind", (sid,), conn):
            w.writerow([r["kind"], r["address"], r["name"], r["previous_address"],
                        r["detail"]])
        w.writerow([])
        w.writerow(["## Findings"])
        w.writerow(["severity", "category", "title", "description", "advice"])
        for r in q("SELECT * FROM findings WHERE scan_id=? ORDER BY id", (sid,), conn):
            w.writerow([r["severity"], r["category"], r["title"], r["description"],
                        r["advice"]])
        return buf.getvalue()
    finally:
        conn.close()


def export_html(sid=None) -> str:
    conn = connect()
    try:
        p = report_payload(sid, conn)
        scan, esc = p["scan"], html_escape
        if not scan:
            return "<!doctype html><html><body><h1>No scans</h1></body></html>"
        counts = {s: scan[s] or 0 for s in SEVERITIES}
        parsed = {"entries": [dict(e, blocks=(e["kind"] == "block"),
                                   normalised=e["name"]) for e in p["entries"]]}
        approved = {a["key"] for a in p["approved"]}
        split = svg_split(parsed)
        rmap = svg_redirect_map(parsed, approved)
        pie = svg_pie([(s, counts[s], SEV_COLOR[s]) for s in SEVERITIES])
        hist = svg_history(p["scans"][::-1])
        frows = "".join(
            f'<tr><td><span class="pill" style="background:{SEV_COLOR[f["severity"]]}">'
            f'{esc(f["severity"].upper())}</span></td>'
            f'<td><b>{esc(f["title"])}</b>'
            f'<div class="desc">{esc(f["description"])}</div>'
            + (f'<pre>{esc(f["evidence"])}</pre>' if f["evidence"] else "")
            + (f'<div class="means"><b>What to do:</b> {esc(f["advice"])}</div>'
               if f["advice"] else "") + "</td></tr>" for f in p["findings"])
        crows = "".join(
            f'<tr><td><span class="pill" style="background:'
            f'{CHANGE_COLOR.get(c["kind"], "#8b8f9b")}">{esc(c["kind"])}</span></td>'
            f'<td class="mono">{esc(c["detail"])}</td></tr>' for c in p["changes"])
        limits = "".join(f"<li>{esc(x)}</li>" for x in p["limitations"])
        return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{APP_SHORT} - {esc(scan['hostname'] or '')}</title><style>
 body{{font:14px/1.55 ui-sans-serif,system-ui,'Segoe UI',Roboto,sans-serif;margin:0;
      background:#0f1115;color:#e6e8ee}}
 .wrap{{max-width:1100px;margin:0 auto;padding:28px 20px 60px}}
 h1{{font-size:22px;margin:0 0 4px}} .meta{{color:#8b8f9b;font-size:12.5px}}
 h2{{font-size:12px;text-transform:uppercase;letter-spacing:.15em;color:#8b8f9b;
     margin:30px 0 12px;border-bottom:1px solid #262a33;padding-bottom:8px}}
 .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin:18px 0}}
 .card{{background:#171a21;border:1px solid #262a33;border-radius:10px;padding:12px 14px}}
 .card .n{{font-size:21px;font-weight:700;font-family:ui-monospace,monospace}}
 .card .l{{font-size:10.5px;text-transform:uppercase;letter-spacing:.11em;color:#8b8f9b}}
 table{{width:100%;border-collapse:collapse;background:#171a21;border:1px solid #262a33;
        border-radius:10px;overflow:hidden;font-size:12.7px}}
 th{{text-align:left;font-size:10.5px;letter-spacing:.11em;text-transform:uppercase;
     color:#8b8f9b;padding:9px 11px;border-bottom:1px solid #262a33;background:#1c2029}}
 td{{padding:8px 11px;border-bottom:1px solid #1e222a;vertical-align:top}}
 .mono{{font-family:ui-monospace,Menlo,monospace;font-size:11.5px;word-break:break-word}}
 .pill{{color:#0f1115;font-weight:700;font-size:10px;padding:2px 8px;border-radius:20px}}
 .desc{{color:#b6bac4;margin-top:4px;max-width:84ch}}
 .means{{margin-top:6px;color:#8fd3b0;font-size:12.4px;max-width:84ch}}
 pre{{background:#0f1115;border:1px solid #262a33;border-radius:6px;padding:9px;
      font-family:ui-monospace,monospace;font-size:11.5px;margin:6px 0 0;overflow:auto;
      white-space:pre-wrap;color:#b6bac4;max-height:300px}}
 .warn{{background:#231a12;border:1px solid #5a3b1c;color:#ffcf9e;padding:12px 14px;
        border-radius:10px;font-size:12.5px;margin:14px 0;white-space:pre-wrap}}
 .note{{background:#12202a;border:1px solid #1c4a5e;color:#a8d8e8;padding:11px 14px;
        border-radius:10px;font-size:12.5px;margin:14px 0}}
 .note ul{{margin:6px 0 0 18px;padding:0}} .note li{{margin:3px 0}}
 .charts{{display:flex;gap:18px;flex-wrap:wrap;align-items:flex-start;margin-bottom:14px}}
 .chart{{margin:0;background:#171a21;border:1px solid #262a33;border-radius:10px;
   padding:14px 16px}}
 .chart.wide{{width:100%}}
 .chart figcaption{{font-size:10.5px;letter-spacing:.12em;text-transform:uppercase;
   color:#8b8f9b;margin-bottom:10px;font-family:ui-monospace,monospace}}
 .chart-row{{display:flex;gap:16px;align-items:center;flex-wrap:wrap}}
 .chart-empty{{background:#171a21;border:1px dashed #31363f;border-radius:10px;padding:18px;
   color:#8b8f9b;font-size:12.5px}}
 .legend{{display:flex;flex-direction:column;gap:6px;min-width:130px}}
 .lg{{display:flex;align-items:center;gap:7px;font-size:12.5px}}
 .lg i{{width:11px;height:11px;border-radius:3px}} .lg span{{flex:1}}
 text.bl{{fill:#8b8f9b;font:10.5px ui-monospace,monospace}}
 text.bv{{fill:#e6e8ee;font:11px ui-monospace,monospace}}
 text.nm{{fill:#e6e8ee;font:12px ui-monospace,monospace}}
 text.addr{{font:12px ui-monospace,monospace}}
 text.pie-n{{fill:#e6e8ee;font:700 16px ui-monospace,monospace}}
 rect.btrack{{fill:#1e222a}}
 footer{{margin-top:36px;color:#6f7685;font-size:12px;border-top:1px solid #262a33;
   padding-top:14px}}
</style></head><body><div class="wrap">
<h1>Hosts file report</h1>
<div class="meta">{esc(scan['hostname'] or '')} &middot; {esc(scan['path'] or '')}
 &middot; {ts_pretty(scan['ts'])} &middot; {scan['elapsed_ms']} ms<br>
 mode {esc(scan['mode'] or '')} owner {esc(scan['owner'] or '')} &middot;
 sha256 {esc(scan['sha256'] or '')}</div>
<div class="note"><b>Blocking is ordinary; redirecting is not.</b>
 {esc(p['blocking_is_ordinary'])}<ul>{limits}</ul></div>
<div class="warn">{esc(DISCLAIMER_LONG)}</div>
<div class="grid">
 <div class="card"><div class="l">Entries</div><div class="n">{scan['entries']}</div></div>
 <div class="card"><div class="l">Blocked</div>
  <div class="n" style="color:#30a46c">{scan['blocks']}</div></div>
 <div class="card"><div class="l">Redirected</div>
  <div class="n" style="color:{'#e5484d' if scan['redirects'] else '#8b8f9b'}">
   {scan['redirects']}</div></div>
 <div class="card"><div class="l">Changes</div><div class="n">{scan['changes']}</div></div>
 <div class="card"><div class="l">Verdict</div>
  <div class="n" style="font-size:14px;color:{scan['band_colour']}">
   {esc(scan['band'] or '')}</div></div>
</div>
<div class="charts">{split}{pie}{hist}</div>
<h2>Redirects</h2><div class="charts">{rmap}</div>
{'<h2>Changes (' + str(len(p['changes'])) + ')</h2><table><tr><th>Kind</th><th>Detail</th>'
 '</tr>' + crows + '</table>' if crows else ''}
<h2>Findings ({len(p['findings'])})</h2>
{'<table><tr><th>Severity</th><th>Detail</th></tr>' + frows + '</table>'
 if frows else '<div class="chart-empty">No findings.</div>'}
<footer>Generated by {APP_NAME} v{VERSION} &middot; {AUTHOR} &middot; {GITHUB}<br>
 The file was read only and never modified. A clean hosts file is not a clean machine - a
 poisoned resolver redirects just as effectively and appears nowhere here.</footer>
</div></body></html>"""
    finally:
        conn.close()


# =============================================================================
# SECTION 8 - Web application
# =============================================================================

CSS = """
:root{--bg:#0f1115;--panel:#171a21;--panel-2:#1c2029;--line:#262a33;--line-2:#31363f;
 --tx:#e6e8ee;--tx-dim:#8b8f9b;--tx-mid:#b6bac4;--accent:#f76808;--ok:#30a46c;
 --warn:#ffb224;--crit:#e5484d;--good:#8fd3b0;
 --mono:ui-monospace,SFMono-Regular,'JetBrains Mono',Menlo,Consolas,monospace;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--tx);
 font:14px/1.55 ui-sans-serif,system-ui,-apple-system,'Segoe UI',Roboto,Arial,sans-serif}
a{color:var(--accent);text-decoration:none} a:hover{text-decoration:underline}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:4px}
header.top{border-bottom:1px solid var(--line);background:var(--panel);position:sticky;top:0;z-index:9}
.hd{max-width:1180px;margin:0 auto;padding:11px 20px;display:flex;align-items:center;gap:14px;
 flex-wrap:wrap}
.brand{font-family:var(--mono);font-weight:700;font-size:15px}
.brand b{color:var(--accent)}
.brand small{display:block;font-weight:400;font-size:10px;letter-spacing:.14em;
 text-transform:uppercase;color:var(--tx-dim)}
nav{display:flex;gap:2px;margin-left:auto;flex-wrap:wrap}
nav a{font-family:var(--mono);font-size:11.5px;text-transform:uppercase;padding:6px 10px;
 border-radius:6px;color:var(--tx-dim)}
nav a:hover{background:var(--panel-2);color:var(--tx);text-decoration:none}
nav a.on{background:var(--accent);color:#0b0d10;font-weight:600}
.wrap{max-width:1180px;margin:0 auto;padding:20px 20px 70px}
.banner{background:#12202a;border:1px solid #1c4a5e;color:#a8d8e8;padding:10px 14px;
 border-radius:9px;font-size:12.3px;margin-bottom:12px;line-height:1.5}
.banner.warn{background:#231a12;border-color:#5a3b1c;color:#ffcf9e}
.banner.bad{background:#2a1216;border-color:#6b2229;color:#ffc9cd}
.banner b{color:#fff} .banner ul{margin:6px 0 0 18px;padding:0}
h1{font-size:19px;margin:0 0 3px} .sub{color:var(--tx-dim);font-size:12.5px;margin-bottom:14px}
h2{font-family:var(--mono);font-size:11.5px;letter-spacing:.16em;text-transform:uppercase;
 color:var(--tx-dim);margin:24px 0 12px;padding-bottom:8px;border-bottom:1px solid var(--line)}
.sub2{color:var(--tx-dim);font-size:11px;font-family:var(--mono)}
.bar{display:flex;gap:9px;align-items:center;flex-wrap:wrap;margin:0 0 16px}
.btn{font-family:var(--mono);font-size:12px;padding:8px 13px;border-radius:7px;cursor:pointer;
 border:1px solid var(--line-2);background:var(--panel-2);color:var(--tx);display:inline-block}
.btn:hover{border-color:var(--accent);text-decoration:none}
.btn.primary{background:var(--accent);border-color:var(--accent);color:#0b0d10;font-weight:700}
.btn.tiny{padding:3px 8px;font-size:10.5px}
input[type=text]{font-family:var(--mono);font-size:12px;padding:8px 10px;
 background:var(--panel-2);color:var(--tx);border:1px solid var(--line-2);border-radius:7px;
 min-width:230px}
.grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(132px,1fr));margin:14px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:13px 15px}
.card .l{font-family:var(--mono);font-size:10.5px;letter-spacing:.13em;text-transform:uppercase;
 color:var(--tx-dim)}
.card .n{font-size:21px;font-weight:700;font-family:var(--mono)}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);
 border-radius:11px;overflow:hidden;font-size:12.7px}
th{text-align:left;font-family:var(--mono);font-size:10.5px;letter-spacing:.11em;
 text-transform:uppercase;color:var(--tx-dim);padding:9px 11px;border-bottom:1px solid var(--line);
 background:var(--panel-2);white-space:nowrap}
td{padding:8px 11px;border-bottom:1px solid #1e222a;vertical-align:top}
tr:last-child td{border-bottom:none} tr:hover td{background:#1b1f27}
.mono{font-family:var(--mono);font-size:11.8px;word-break:break-word}
.num{font-family:var(--mono);font-size:11.8px;text-align:right}
.pill{display:inline-block;color:#0b0d10;font-weight:700;font-size:10px;padding:2px 8px;
 border-radius:20px;font-family:var(--mono);white-space:nowrap}
.tag{display:inline-block;font-family:var(--mono);font-size:10px;padding:1px 6px;border-radius:5px;
 border:1px solid var(--line-2);color:var(--tx-dim);margin-left:4px}
.tag.good{border-color:#1e5138;color:#7fd9ab} .tag.bad{border-color:#5a2326;color:#ff9b9e}
.desc{color:var(--tx-mid);margin-top:4px;max-width:84ch}
.means{margin-top:6px;color:var(--good);font-size:12.4px;max-width:84ch}
pre{background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:9px 11px;
 font-family:var(--mono);font-size:11.5px;margin:6px 0 0;max-height:300px;overflow:auto;
 white-space:pre-wrap;color:var(--tx-mid)}
.charts{display:flex;gap:18px;flex-wrap:wrap;align-items:flex-start;margin-bottom:14px}
.chart{margin:0;background:var(--panel);border:1px solid var(--line);border-radius:11px;
 padding:14px 16px}
.chart.wide{width:100%}
.chart figcaption{font-family:var(--mono);font-size:10.5px;letter-spacing:.13em;
 text-transform:uppercase;color:var(--tx-dim);margin-bottom:10px}
.chart-row{display:flex;gap:16px;align-items:center;flex-wrap:wrap}
.chart-empty{background:var(--panel);border:1px dashed var(--line-2);border-radius:11px;
 padding:20px;color:var(--tx-dim);font-size:12.5px;flex:1;min-width:240px}
.legend{display:flex;flex-direction:column;gap:6px;min-width:130px}
.lg{display:flex;align-items:center;gap:7px;font-size:12.5px}
.lg i{width:11px;height:11px;border-radius:3px;flex:none} .lg span{flex:1}
.lg b{font-family:var(--mono)}
text.bl{fill:#8b8f9b;font:10.5px var(--mono)} text.bv{fill:#e6e8ee;font:11px var(--mono)}
text.nm{fill:#e6e8ee;font:12px var(--mono)} text.addr{font:12px var(--mono)}
text.pie-n{fill:#e6e8ee;font:700 16px var(--mono)} rect.btrack{fill:#1e222a}
.empty{background:var(--panel);border:1px dashed var(--line-2);border-radius:11px;padding:28px;
 text-align:center;color:var(--tx-dim)}
.empty b{display:block;color:var(--tx);margin-bottom:6px;font-size:15px}
footer{max-width:1180px;margin:0 auto;padding:16px 20px 40px;color:#6f7685;font-size:11.5px;
 border-top:1px solid var(--line);line-height:1.7}
@media (max-width:640px){.hd{padding:10px 14px} .wrap{padding:14px 14px 50px}
 nav{margin-left:0;width:100%} .card .n{font-size:18px} th,td{padding:7px 8px}}
"""

BASE_TPL = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ page }} - """ + APP_SHORT + """</title><style>""" + CSS + """</style></head><body>
<header class="top"><div class="hd">
 <div class="brand"><b>HOSTSGUARD</b> <small>hosts file tampering detector</small></div>
 <nav>
  <a href="{{ url_for('page_overview') }}" class="{{ 'on' if nav=='overview' }}">Overview</a>
  <a href="{{ url_for('page_entries') }}" class="{{ 'on' if nav=='entries' }}">Entries</a>
  <a href="{{ url_for('page_changes') }}" class="{{ 'on' if nav=='changes' }}">Changes</a>
  <a href="{{ url_for('page_learn') }}" class="{{ 'on' if nav=='learn' }}">Learn</a>
 </nav></div></header>
<div class="wrap">
 <div class="banner"><b>Blocking is ordinary; redirecting is not.</b>
  """ + BLOCK_NOT_TAMPER + """</div>
 {% if error %}<div class="banner bad"><b>That failed:</b> {{ error }}</div>{% endif %}
 {% if flash %}<div class="banner">{{ flash }}</div>{% endif %}
 {% block body %}{% endblock %}
</div>
<footer>""" + APP_NAME + """ v""" + VERSION + """ &middot; built by """ + AUTHOR + """ &middot;
 <a href=\"""" + GITHUB + """\" rel="noopener">GitHub</a> &middot;
 <a href=\"""" + LINKEDIN + """\" rel="noopener">LinkedIn</a><br>
 Read-only: the hosts file is never modified. A clean hosts file is not a clean machine - a
 poisoned resolver or rogue DHCP server redirects just as effectively and appears nowhere
 here.</footer></body></html>"""

SCANBAR = """
<div class="bar">
 <form method="post" action="{{ url_for('do_scan') }}" style="display:flex;gap:8px">
  <input type="text" name="path" value="{{ path or '' }}" placeholder="hosts file path
   (blank for the system one)">
  <button class="btn primary" type="submit">Check now</button></form>
 {% if scan %}
 <a class="btn" href="{{ url_for('export', fmt='html') }}?scan={{ scan.id }}">Export HTML</a>
 <a class="btn" href="{{ url_for('export', fmt='json') }}?scan={{ scan.id }}">JSON</a>
 <a class="btn" href="{{ url_for('export', fmt='csv') }}?scan={{ scan.id }}">CSV</a>
 {% endif %}
</div>"""

EMPTY_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Overview</h1>""" + SCANBAR + """
<div class="empty"><b>Nothing checked yet</b>
 It reads the hosts file, separates names that go nowhere from names that go somewhere, and
 reports the second kind.
 <div class="mono" style="margin-top:12px;color:var(--tx-dim)">
  from the terminal: python3 hostsguard.py check</div></div>
{% endblock %}"""

OVERVIEW_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Overview</h1>
<div class="sub">Scan #{{ scan.id }} &middot; {{ scan.path }} &middot;
 {{ ts_pretty(scan.ts) }} &middot; mode {{ scan.mode }} owner {{ scan.owner }}</div>
""" + SCANBAR + """
{% if scan.world_writable %}
<div class="banner bad"><b>The hosts file is world-writable.</b> Fix that before anything
 else here: whatever it says today, any user can change it.</div>
{% endif %}
<div class="grid">
 <div class="card"><div class="l">Entries</div><div class="n">{{ scan.entries }}</div></div>
 <div class="card"><div class="l">Blocked</div>
  <div class="n" style="color:#30a46c">{{ scan.blocks }}</div>
  <div class="l">goes nowhere</div></div>
 <div class="card"><div class="l">Redirected</div>
  <div class="n" style="color:{{ '#e5484d' if scan.redirects else '#8b8f9b' }}">
   {{ scan.redirects }}</div><div class="l">goes somewhere</div></div>
 <div class="card"><div class="l">Changes</div><div class="n">{{ scan.changes }}</div></div>
 <div class="card"><div class="l">Verdict</div>
  <div class="n" style="font-size:14px;color:{{ scan.band_colour }}">{{ scan.band }}</div></div>
</div>
<div class="charts">{{ split|safe }}{{ pie|safe }}{{ hist|safe }}</div>
<h2>Redirects</h2><div class="charts">{{ rmap|safe }}</div>
{% if changes %}
<h2>What changed</h2>
<table><tr><th>Kind</th><th>Detail</th></tr>
{% for c in changes %}<tr>
 <td><span class="pill" style="background:{{ chg.get(c.kind,'#8b8f9b') }}">{{ c.kind }}</span></td>
 <td class="mono">{{ c.detail }}</td></tr>{% endfor %}</table>
{% endif %}
<h2>Findings</h2>
{% if findings %}
<table><tr><th>Severity</th><th>Detail</th></tr>
{% for f in findings %}
<tr><td><span class="pill" style="background:{{ sev[f.severity] }}">
 {{ f.severity|upper }}</span></td>
 <td><b>{{ f.title }}</b><div class="desc">{{ f.description }}</div>
  {% if f.evidence %}<pre>{{ f.evidence }}</pre>{% endif %}
  {% if f.advice %}<div class="means"><b>What to do:</b> {{ f.advice }}</div>{% endif %}
 </td></tr>{% endfor %}</table>
{% else %}<div class="empty">No findings.</div>{% endif %}
{% endblock %}"""

ENTRIES_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Entries</h1><div class="sub">{{ rows|length }} shown from the latest check.</div>
<div class="bar"><form method="get" style="display:flex;gap:8px;flex-wrap:wrap">
 <select name="kind" style="font-family:var(--mono);padding:8px;background:var(--panel-2);
  color:var(--tx);border:1px solid var(--line-2);border-radius:7px">
  <option value="">All kinds</option>
  <option value="redirect" {{ 'selected' if f_kind=='redirect' }}>redirected only</option>
  <option value="block" {{ 'selected' if f_kind=='block' }}>blocked only</option>
 </select>
 <input type="text" name="qq" value="{{ f_q }}" placeholder="name or address">
 <button class="btn" type="submit">Filter</button>
 <a class="btn" href="{{ url_for('page_entries') }}">Reset</a>
</form></div>
{% if rows %}
<table><tr><th>Line</th><th>Address</th><th>Name</th><th>Kind</th><th>Category</th>
 <th>Baseline</th></tr>
{% for r in rows %}<tr>
 <td class="num">{{ r.line }}</td><td class="mono">{{ r.address }}</td>
 <td class="mono">{{ r.name }}
  {% if r.confusable %}<span class="tag bad">confusable</span>{% endif %}
  {% if r.shadowed_by %}<span class="tag">shadowed by line {{ r.shadowed_by }}</span>{% endif %}</td>
 <td class="sub2">{{ r.kind }}{% if r.scope %} &middot; {{ r.scope }}{% endif %}</td>
 <td class="sub2">{{ r.category or '-' }}</td>
 <td>{% if r.approved %}<span class="tag good">approved</span>
   <form method="post" action="{{ url_for('do_revoke') }}" style="display:inline">
    <input type="hidden" name="address" value="{{ r.address }}">
    <input type="hidden" name="name" value="{{ r.name }}">
    <button class="btn tiny" type="submit">remove</button></form>
  {% elif r.kind == 'redirect' %}
   <form method="post" action="{{ url_for('do_approve') }}" style="display:inline">
    <input type="hidden" name="address" value="{{ r.address }}">
    <input type="hidden" name="name" value="{{ r.name }}">
    <button class="btn tiny" type="submit">approve</button></form>
  {% endif %}</td></tr>{% endfor %}</table>
{% else %}<div class="empty"><b>No entries match</b></div>{% endif %}
{% endblock %}"""

CHANGES_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Changes</h1><div class="sub">Every change recorded across all checks.</div>
{% if rows %}
<table><tr><th>When</th><th>Scan</th><th>Kind</th><th>Detail</th><th>Category</th></tr>
{% for c in rows %}<tr>
 <td class="mono">{{ (c.ts or '')[:19].replace('T',' ') }}</td>
 <td class="mono"><a href="{{ url_for('page_overview') }}?scan={{ c.scan_id }}">
  #{{ c.scan_id }}</a></td>
 <td><span class="pill" style="background:{{ chg.get(c.kind,'#8b8f9b') }}">{{ c.kind }}</span>
  {% if c.entry_kind == 'redirect' %}<span class="tag bad">redirect</span>{% endif %}</td>
 <td class="mono">{{ c.detail }}</td><td class="sub2">{{ c.category or '-' }}</td>
</tr>{% endfor %}</table>
{% else %}<div class="empty"><b>No changes recorded</b>
 The first check becomes the baseline; changes are measured from there.</div>{% endif %}
{% endblock %}"""

LEARN_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Why the hosts file matters</h1>
<div class="banner"><b>It is consulted before DNS.</b> A line in it silently overrides the
 entire naming system for that name - no lookup, no DNSSEC, and no certificate warning until
 the connection is already being made somewhere else. That makes it the cheapest way to
 redirect a machine, and malware has used it for decades.</div>
<h2>Blocking versus redirecting</h2>
<div class="desc"><b>Blocking</b> sends a name to 0.0.0.0, 127.0.0.1 or :: - it goes nowhere.
 Millions of machines run ad-blocking hosts files with hundreds of thousands of such entries.
 That is deliberate and benign, and a tool that treated it as tampering would drown the one
 line that matters.<br><br>
 <b>Redirecting</b> sends a name to a real, routable address - traffic goes THERE instead.
 That is rare in normal use and is the shape of an attack. A 200,000-line ad blocker produces
 one calm informational line here; a single entry pointing a bank at a public address is
 reported as critical.</div>
<h2>What gets weighted most</h2>
<div class="desc">Redirecting <b>banks, identity providers, security vendors and package
 registries</b> is treated as critical - the first two harvest credentials, the third stops
 you being protected, and the fourth can substitute the code you install.<br><br>
 <b>Blocking</b> security vendors and update services is its own kind of attack: it is how
 malware ensures a machine never downloads a fix. It is also what some privacy blocklists do
 on purpose, so it is reported as high rather than critical and the advice says to check
 which.</div>
<h2>Names built to be misread</h2>
<div class="desc">A name can mix scripts so it renders identically to one you trust -
 Cyrillic <span class="mono">а</span> is not Latin <span class="mono">a</span>. Punycode
 (<span class="mono">xn--</span>) encodes those as ASCII. This tool decodes them and lists the
 actual characters, because the rendered name is exactly what you cannot rely on.</div>
<h2>Entries that do not do what they look like</h2>
<div class="desc">The resolver uses the <b>first</b> match for a name. A later line pointing
 the same name somewhere else never takes effect - so the entry you can see may not be the one
 in force, which is a neat way to hide a change in plain sight. Tabs, trailing whitespace and
 a byte order mark can all make a line read differently to a human than to a parser.</div>
<h2>What this cannot tell you</h2>
<div class="banner warn"><ul>
 <li>Whether an entry is legitimate. A developer's staging override and an attacker's redirect
  are identical. Approve yours and the tool goes quiet about them.</li>
 <li>Anything about DNS itself. A poisoned resolver or rogue DHCP server redirects a machine
  just as effectively and appears nowhere here.</li>
 <li>Anything from before the first run - that check becomes the baseline.</li>
 <li>Whether a name absent from its curated sensitive list is safe. It is not exhaustive.</li>
</ul></div>
<h2>It never writes</h2>
<div class="desc">There is deliberately no command that edits, cleans or restores the file: a
 tool that repairs a hosts file automatically is one that can break name resolution on a
 machine you are trying to diagnose.</div>
{% endblock %}"""

TEMPLATES = {"base.html": BASE_TPL, "empty.html": EMPTY_TPL, "overview.html": OVERVIEW_TPL,
             "entries.html": ENTRIES_TPL, "changes.html": CHANGES_TPL,
             "learn.html": LEARN_TPL}

try:
    from flask import (Flask, Response, jsonify, redirect, render_template, request, url_for)
    from jinja2 import ChoiceLoader, DictLoader
    HAVE_FLASK = True
except Exception:  # pragma: no cover
    HAVE_FLASK = False


def build_app():
    if not HAVE_FLASK:
        raise SystemExit("Flask is not installed. Install it with:  pip install flask\n"
                         "(The CLI works without Flask; only the web app needs it.)")
    app = Flask(__name__)
    app.jinja_loader = ChoiceLoader([DictLoader(TEMPLATES), app.jinja_loader])

    def ctx(nav, **kw):
        base = {"nav": nav, "page": nav.capitalize(), "sev": SEV_COLOR,
                "chg": CHANGE_COLOR, "ts_pretty": ts_pretty, "scan": None, "path": None,
                "error": request.args.get("error"), "flash": request.args.get("flash")}
        base.update(kw)
        return base

    @app.route("/")
    def page_overview():
        conn = connect()
        try:
            init_db(conn)
            try:
                sid = int(request.args.get("scan", "") or 0)
            except ValueError:
                sid = 0
            scan = scan_summary(sid, conn) if sid else (
                scan_summary(latest_scan_id(conn), conn) if latest_scan_id(conn) else None)
            if not scan:
                return render_template("empty.html", **ctx("overview"))
            p = report_payload(scan["id"], conn)
            parsed = {"entries": [dict(e, blocks=(e["kind"] == "block"),
                                       normalised=e["name"]) for e in p["entries"]]}
            approved = {a["key"] for a in p["approved"]}
            counts = {s: scan[s] or 0 for s in SEVERITIES}
            return render_template("overview.html", **ctx(
                "overview", scan=scan, path=scan["path"], findings=p["findings"],
                changes=p["changes"], split=svg_split(parsed),
                rmap=svg_redirect_map(parsed, approved),
                pie=svg_pie([(s, counts[s], SEV_COLOR[s]) for s in SEVERITIES]),
                hist=svg_history(p["scans"][::-1])))
        finally:
            conn.close()

    @app.post("/scan")
    def do_scan():
        import urllib.parse as up
        path = (request.form.get("path") or "").strip() or None
        try:
            sid, _m, _p, _c, _f = run_scan(path, note="from the web UI")
        except Exception as e:
            log_event("ERROR", "scan", str(e))
            return redirect(url_for("page_overview") + "?error=" + up.quote(str(e)))
        return redirect(url_for("page_overview") + f"?scan={sid}")

    @app.route("/entries")
    def page_entries():
        conn = connect()
        try:
            init_db(conn)
            sid = latest_scan_id(conn)
            if not sid:
                return render_template("entries.html", **ctx("entries", rows=[],
                                                             f_kind="", f_q=""))
            kind = request.args.get("kind", "").strip()
            term = request.args.get("qq", "").strip().lower()
            approved = {a["key"] for a in report_payload(sid, conn)["approved"]}
            rows = []
            for r in q("SELECT * FROM observations WHERE scan_id=? ORDER BY line",
                       (sid,), conn):
                d = dict(r)
                d["approved"] = f"{d['address']} {d['name']}" in approved
                if kind and d["kind"] != kind:
                    continue
                if term and term not in f"{d['address']} {d['name']}".lower():
                    continue
                rows.append(d)
            return render_template("entries.html", **ctx(
                "entries", rows=rows[:1000], f_kind=kind,
                f_q=request.args.get("qq", "")))
        finally:
            conn.close()

    @app.post("/approve")
    def do_approve():
        import urllib.parse as up
        a = (request.form.get("address") or "").strip()
        n = (request.form.get("name") or "").strip()
        if a and n:
            approve_entry(a, n, "approved from the web UI")
        return redirect(url_for("page_entries") + "?flash="
                        + up.quote(f"{a} {n} approved. It will not be reported again unless "
                                   f"the address changes."))

    @app.post("/revoke")
    def do_revoke():
        a = (request.form.get("address") or "").strip()
        n = (request.form.get("name") or "").strip()
        if a and n:
            revoke_entry(a, n)
        return redirect(url_for("page_entries"))

    @app.route("/changes")
    def page_changes():
        conn = connect()
        try:
            init_db(conn)
            return render_template("changes.html", **ctx(
                "changes", rows=q("SELECT * FROM changes ORDER BY id DESC LIMIT 300",
                                  (), conn)))
        finally:
            conn.close()

    @app.route("/learn")
    def page_learn():
        return render_template("learn.html", **ctx("learn"))

    @app.route("/export/<fmt>")
    def export(fmt):
        try:
            sid = int(request.args.get("scan", "") or 0) or None
        except ValueError:
            sid = None
        fmt = fmt.lower()
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        if fmt == "json":
            body, mime = export_json(sid), "application/json"
        elif fmt == "csv":
            body, mime = export_csv(sid), "text/csv"
        elif fmt == "html":
            body, mime = export_html(sid), "text/html"
        else:
            return Response("Unsupported format. Use json, csv or html.", 400,
                            mimetype="text/plain")
        log_event("INFO", "export", f"Exported the report as {fmt.upper()}", sid)
        return Response(body, mimetype=mime, headers={
            "Content-Disposition": f'attachment; filename="hostsguard-{stamp}.{fmt}"'})

    @app.route("/api/summary")
    def api_summary():
        sid = latest_scan_id()
        if not sid:
            return jsonify({"error": "no scans yet"}), 404
        return jsonify({"tool": APP_NAME, "version": VERSION, "read_only": True,
                        "blocking_is_ordinary": True,
                        "sees_only_this_file": True,
                        "disclaimer": DISCLAIMER_SHORT, "scan": scan_summary(sid)})

    @app.errorhandler(404)
    def nf(_e):
        return Response("404 - valid pages: / /entries /changes /learn", 404,
                        mimetype="text/plain")

    return app


def serve(host: str, port: int, debug: bool = False):
    app = build_app()
    init_db()
    log_event("INFO", "web", f"Web app started on http://{host}:{port}")
    print(f"\n  {APP_NAME} v{VERSION} - by {AUTHOR}")
    print(f"  {'-' * 66}")
    print(f"  Web app : http://{'127.0.0.1' if host == '0.0.0.0' else host}:{port}")
    print(f"  Hosts   : {default_hosts_path()}")
    print(f"  Database: {os.path.abspath(db_path())}")
    if host == "0.0.0.0":
        print("  WARNING : bound to 0.0.0.0 - this UI has no authentication and can read\n"
              "            any file path given to it. Use 127.0.0.1.")
    print(f"  {textwrap.fill(DISCLAIMER_SHORT, 66, subsequent_indent='  ')}")
    print(f"  {'-' * 66}\n  Press Ctrl+C to stop.\n")
    app.run(host=host, port=port, debug=debug, use_reloader=False)


# =============================================================================
# SECTION 9 - Command line interface
# =============================================================================

def line(char="-", n=78):
    print(char * n)


def banner():
    print(f"\n{APP_NAME} v{VERSION}  |  {AUTHOR}")
    line()
    print(textwrap.fill(DISCLAIMER_SHORT, 78))
    line()


def _print_findings(rows, limit=None, quiet=False):
    shown = [f for f in rows if not (quiet and f["severity"] == "info")]
    for f in (shown[:limit] if limit else shown):
        print(f"\n  [{f['severity'].upper():^8}] {f['title']}")
        for l in textwrap.wrap(f["description"], 70):
            print(f"      {l}")
        if f.get("evidence"):
            for l in str(f["evidence"]).splitlines()[:10]:
                for w in textwrap.wrap(l, 70) or [""]:
                    print(f"      {w}")
        if f.get("advice"):
            for l in textwrap.wrap("what to do: " + f["advice"], 70):
                print(f"      {l}")


def cmd_check(a):
    banner()
    sid, meta, parsed, changes, findings = run_scan(a.path, note=a.note or "")
    scan = scan_summary(sid)
    print(f"File   : {meta.get('path')}")
    if meta.get("error"):
        print(f"Error  : {meta['error']}")
        line()
        _print_findings(findings)
        return 1
    print(f"Mode   : {meta['mode']}  owner {meta['owner']}  {fmt_bytes(meta['size'])}")
    print(f"Changed: {meta['mtime'][:19].replace('T', ' ')} UTC")
    print(f"sha256 : {meta['sha256']}")
    line("=")
    print(f"  {len(parsed['entries'])} ENTRY(IES)   "
          f"{scan['blocks']} blocked, {scan['redirects']} redirected")
    print(f"  {scan['band'].upper()}   (score {scan['score']})")
    line("=")
    redirects = [e for e in parsed["entries"] if e["kind"] == "redirect"]
    if redirects:
        print("  NAMES THAT GO SOMEWHERE")
        for e in redirects[:a.limit]:
            tag = f"  [{e['category']}]" if e["category"] else ""
            print(f"   line {e['line']:>4}  {e['address']:<16} {e['normalised']}{tag}")
        if len(redirects) > a.limit:
            print(f"   ... {len(redirects) - a.limit} more")
        line()
    else:
        print("  Nothing is redirected - every entry sends its name nowhere.")
        line()
    if changes:
        print(f"  CHANGES ({len(changes)})")
        for c in changes[:a.limit]:
            mark = "  !" if c.get("entry_kind") == "redirect" else "   "
            print(f" {mark} {c['kind']:<9} {c['detail']}")
        line()
    _print_findings(findings, a.show, a.quiet)
    line()
    print(textwrap.fill("  " + BLOCK_NOT_TAMPER, 78))
    line()
    crit = [f for f in findings if f["severity"] in ("critical", "high")]
    if a.fail_on_redirect and any(f["category"] == "Redirect" and
                                  f["severity"] in ("critical", "high") for f in findings):
        print("  Exiting non-zero: a sensitive name is redirected.")
        return 2
    if a.fail_over is not None and (scan["score"] or 0) > a.fail_over:
        print(f"  Exiting non-zero: {scan['score']} is above --fail-over {a.fail_over}")
        return 2
    return 0


def cmd_watch(a):
    banner()
    print(f"Checking every {a.interval}s"
          + (f", {a.count} times" if a.count else " until Ctrl+C") + ".")
    print("Only changes are printed - a quiet run means nothing changed.\n")
    n = 0
    try:
        while True:
            n += 1
            sid, meta, parsed, changes, findings = run_scan(a.path, note="watch")
            stamp = datetime.now().strftime("%H:%M:%S")
            alerts = [f for f in findings if f["severity"] in ("critical", "high")]
            if changes or (alerts and n == 1):
                print(f"  {stamp}  #{sid}  {len(parsed['entries'])} entry(ies), "
                      f"{len(changes)} change(s)")
                for c in changes:
                    mark = "  !!" if c.get("entry_kind") == "redirect" else "    "
                    print(f"  {mark}  {c['kind']:<9} {c['detail']}")
                for f in alerts:
                    print(f"    [{f['severity'].upper()}] {f['title']}")
            elif not a.quiet:
                print(f"  {stamp}  #{sid}  no change")
            if a.count and n >= a.count:
                break
            time.sleep(a.interval)
    except KeyboardInterrupt:
        print("\nStopped.")
    line()
    return 0


def cmd_entries(a):
    sid = latest_scan_id()
    if not sid:
        print("Nothing checked yet. Run:  check")
        return 0
    approved = approved_map()
    rows = [dict(r) for r in q("SELECT * FROM observations WHERE scan_id=? ORDER BY line",
                               (sid,))]
    if a.redirects_only:
        rows = [r for r in rows if r["kind"] == "redirect"]
    if a.name:
        rows = [r for r in rows if a.name.lower() in r["name"].lower()]
    print(f"  {'LINE':>5}  {'ADDRESS':<16} {'NAME':<40} KIND")
    line()
    for r in rows[:a.limit]:
        tags = []
        if f"{r['address']} {r['name']}" in approved:
            tags.append("approved")
        if r["category"]:
            tags.append(r["category"])
        if r["confusable"]:
            tags.append("CONFUSABLE")
        if r["shadowed_by"]:
            tags.append(f"shadowed by {r['shadowed_by']}")
        print(f"  {r['line']:>5}  {r['address']:<16} {r['name'][:39]:<40} {r['kind']}"
              + (f"  [{', '.join(tags)}]" if tags else ""))
    line()
    print(f"  {min(len(rows), a.limit)} of {len(rows)} shown")
    return 0


def cmd_approve(a):
    key = approve_entry(a.address, a.name, a.note or "")
    print(f"Approved {key}")
    print(textwrap.fill(
        "Approval is by address and name together, so if either changes the entry is "
        "reported again.", 78))
    return 0


def cmd_revoke(a):
    n = revoke_entry(a.address, a.name)
    print("Removed from the approved list." if n else "That entry was not approved.")
    return 0


def cmd_learn(_a):
    banner()
    print(textwrap.dedent("""\
        WHY THE HOSTS FILE MATTERS

          It is consulted BEFORE DNS. A line in it silently overrides the entire
          naming system for that name - no lookup, no DNSSEC, no certificate
          warning until the connection is already being made somewhere else. That
          makes it the cheapest way to redirect a machine, and malware has used it
          for decades.

        BLOCKING IS ORDINARY. REDIRECTING IS NOT.

          BLOCK     name -> 0.0.0.0, 127.0.0.1 or ::  - the name goes nowhere.
                    Millions of machines run ad-blocking hosts files with hundreds
                    of thousands of these. Deliberate and benign.

          REDIRECT  name -> a real, routable address  - traffic goes THERE.
                    Rare in normal use, and the shape of an attack.

          A 200,000-line ad blocker produces one calm informational line here. A
          single entry pointing a bank at a public address is critical.

        WHAT IS WEIGHTED MOST

          Redirecting banks, identity providers, security vendors and package
          registries is critical: the first two harvest credentials, the third
          stops you being protected, the fourth substitutes the code you install.

          BLOCKING security vendors and update services is its own attack - it is
          how malware ensures a machine never downloads a fix. It is also what
          some privacy blocklists do deliberately, so it is high rather than
          critical, and the advice says to check which.

        NAMES BUILT TO BE MISREAD

          A name can mix scripts so it renders identically to one you trust:
          Cyrillic 'а' is not Latin 'a'. Punycode (xn--) encodes those as ASCII.
          This tool decodes them and lists the actual characters, because the
          rendered name is precisely what you cannot rely on.

        ENTRIES THAT DO NOT DO WHAT THEY LOOK LIKE

          The resolver uses the FIRST match for a name. A later line pointing the
          same name elsewhere never takes effect - so the entry you can see may
          not be the one in force. Tabs, trailing whitespace and a byte order mark
          all make a line read differently to a human than to a parser.

        WHAT THIS CANNOT TELL YOU

          Whether an entry is legitimate - a developer's staging override and an
          attacker's redirect are identical. Approve yours.

          Anything about DNS itself. A poisoned resolver or rogue DHCP server
          redirects a machine just as effectively and appears nowhere here. A
          clean hosts file is not a clean machine.

          Anything from before the first run: that check becomes the baseline.

        IT NEVER WRITES

          There is deliberately no command that edits, cleans or restores the
          file. A tool that repairs a hosts file automatically is one that can
          break name resolution on a machine you are trying to diagnose.
        """))
    line()


def cmd_scans(a):
    rows = q("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (a.limit,))
    if not rows:
        print("Nothing checked yet.")
        return 0
    print(f"{'ID':>4}  {'WHEN (UTC)':<20} {'ENTRIES':>7} {'CHG':>4} {'SCORE':>6}  BAND")
    line()
    for s in rows:
        print(f"{s['id']:>4}  {s['ts'][:19].replace('T', ' '):<20} {s['entries']:>7} "
              f"{s['changes']:>4} {s['score']:>6}  {s['band']}")
    return 0


def cmd_export(a):
    sid = a.scan or latest_scan_id()
    if not sid:
        print("Nothing to export yet.")
        return 1
    fmt = a.format.lower()
    body = {"json": export_json, "csv": export_csv, "html": export_html}[fmt](sid)
    out = a.out or f"hostsguard-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.{fmt}"
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(body)
    print(f"Wrote {out} ({len(body):,} bytes)")
    return 0


def cmd_logs(a):
    sql, args = "SELECT * FROM audit_log WHERE 1=1", []
    if a.level:
        sql += " AND level=?"
        args.append(a.level.upper())
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(a.limit)
    rows = q(sql, tuple(args))
    if not rows:
        print("No log entries.")
        return 0
    for e in reversed(rows):
        print(f"{e['ts'][:19].replace('T', ' ')}  {e['level']:<5} {e['source']:<10} "
              f"{e['message']}")
    return 0


def cmd_purge(a):
    conn = connect()
    try:
        if a.all:
            for t in ("findings", "changes", "observations", "scans", "audit_log"):
                conn.execute(f"DELETE FROM {t}")
            if a.approved:
                conn.execute("DELETE FROM approved")
            conn.commit()
            print("All scans, entries, changes and logs deleted."
                  + (" Approvals cleared too." if a.approved else " Approvals kept."))
            return 0
        rows = q("SELECT id FROM scans ORDER BY id DESC", (), conn)
        drop = [r["id"] for r in rows[a.keep:]]
        for sid in drop:
            for t in ("findings", "changes", "observations"):
                conn.execute(f"DELETE FROM {t} WHERE scan_id=?", (sid,))
            conn.execute("DELETE FROM scans WHERE id=?", (sid,))
        conn.commit()
        print(f"Purged {len(drop)} scan(s); kept the newest {a.keep}.")
        return 0
    finally:
        conn.close()


def cmd_serve(a):
    serve(a.host, a.port, a.debug)


def cmd_version(_a):
    banner()
    print(f"  Python     : {platform.python_version()} ({sys.platform})")
    print(f"  Flask      : {'yes' if HAVE_FLASK else 'NOT INSTALLED - web app unavailable'}")
    print(f"  Hosts file : {default_hosts_path()}")
    print(f"  Known names: {len(_SENSITIVE_INDEX)} across {len(SENSITIVE)} categories "
          f"(a curated selection, not exhaustive)")
    print(f"  Database   : {os.path.abspath(db_path())}")
    print(f"  GitHub     : {GITHUB}")
    line()
    print(DISCLAIMER_LONG)
    line()


# =============================================================================
# SECTION 10 - Self test
# =============================================================================

def _write(path: str, text: str) -> str:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


def cmd_selftest(_a=None) -> int:
    import tempfile
    passed, failed = [], []

    def check(name, cond, detail=""):
        (passed if cond else failed).append(name)
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              f"{'  <- ' + str(detail) if detail and not cond else ''}")

    banner()
    print("SELF TEST - fixtures are written to a temporary directory and parsed.\n")
    original = db_path()
    tmp = tempfile.mkdtemp(prefix="hostsguard-selftest-")
    set_db_path(os.path.join(tmp, "selftest.db"))

    def scan_text(text, approved=None):
        p = _write(os.path.join(tmp, "hosts"), text)
        meta = read_hosts(p)
        parsed = parse_hosts(meta["text"])
        return meta, parsed, analyse(meta, parsed, approved or {})

    try:
        print(" Address classification")
        for addr, kind, blocks in (("0.0.0.0", "block", True), ("127.0.0.1", "block", True),
                                   ("::", "block", True), ("::1", "block", True),
                                   ("203.0.113.5", "redirect", False),
                                   ("192.168.1.5", "redirect", False),
                                   ("224.0.0.1", "unusual", False)):
            c = classify_address(addr)
            check(f"{addr} is a {kind}", c["kind"] == kind and c["blocks"] == blocks, c)
        check("a non-address is rejected", not classify_address("nonsense")["valid"])
        check("a private redirect is marked private",
              classify_address("10.0.0.1")["scope"] == "private")
        check("a public redirect is marked public",
              classify_address("8.8.8.8")["scope"] == "public")

        print("\n Sensitive names")
        check("an exact name is categorised",
              sensitive_category("paypal.com")[0] == "banking")
        check("a subdomain inherits its parent's category",
              sensitive_category("login.paypal.com")[0] == "banking")
        check("a security vendor is categorised",
              sensitive_category("virustotal.com")[0] == "security")
        check("an unrelated name has no category",
              sensitive_category("example.invalid")[0] is None)
        check("redirect severities are set for every category",
              set(CATEGORY_SEVERITY_REDIRECT) == set(SENSITIVE))
        check("block severities are set for every category",
              set(CATEGORY_SEVERITY_BLOCK) == set(SENSITIVE))

        print("\n Confusable names")
        s = script_analysis("xn--80ak6aa92e.com")
        check("punycode is detected and decoded", s["punycode"] and s["decoded"], s)
        check("mixed scripts are detected", s["mixed"] and s["confusable"])
        check("the offending characters are named",
              any("CYRILLIC" in c for c in s["suspicious_chars"]), s["suspicious_chars"])
        check("a plain ASCII name is clean",
              not script_analysis("example.com")["confusable"])

        print("\n Parsing")
        meta, parsed, _f = scan_text(
            "127.0.0.1 localhost\n"
            "# a comment\n"
            "\n"
            "203.0.113.5 a.example.com b.example.com\n"
            "not-an-address c.example.com\n"
            "198.51.100.1\n")
        check("entries are parsed", len(parsed["entries"]) == 3, parsed["entries"])
        check("multiple names on one line each become an entry",
              sum(1 for e in parsed["entries"] if e["line"] == 4) == 2)
        check("aliases are recorded",
              any(e["aliases"] for e in parsed["entries"] if e["line"] == 4))
        check("comments are counted, not parsed", parsed["comments"] == 1)
        check("an invalid address makes the line malformed",
              any("not an IP address" in m["why"] for m in parsed["malformed"]),
              parsed["malformed"])
        check("an address with no name is malformed",
              any("no name" in m["why"] for m in parsed["malformed"]))
        _m, p2, _f = scan_text("127.0.0.1 x.example.com # trailing comment\n")
        check("a mid-line comment is stripped from the names",
              p2["entries"][0]["normalised"] == "x.example.com"
              and p2["entries"][0]["comment"] == "trailing comment", p2["entries"][0])

        print("\n Blocking is ordinary")
        big = "127.0.0.1 localhost\n" + "".join(
            f"0.0.0.0 ads{i}.tracker.example\n" for i in range(BLOCKLIST_THRESHOLD + 100))
        meta, parsed, f = scan_text(big)
        check("a large blocklist produces no critical or high finding",
              not any(x["severity"] in ("critical", "high") for x in f),
              [x["title"] for x in f if x["severity"] in ("critical", "high")])
        check("it scores zero", risk_score(f) == 0.0, risk_score(f))
        check("and it is reported once as a blocklist",
              any("names are blocked" in x["title"] for x in f), [x["title"] for x in f])

        print("\n Redirecting is not")
        meta, parsed, f = scan_text("127.0.0.1 localhost\n203.0.113.66 paypal.com\n")
        crit = [x for x in f if x["severity"] == "critical"]
        check("a bank redirected to a public address is CRITICAL",
              crit and "paypal.com" in crit[0]["title"], [x["title"] for x in f])
        check("the advice explains there will be no warning",
              crit and "no lookup to fail" in crit[0]["advice"])
        for name, cat in (("accounts.google.com", "identity"),
                          ("registry.npmjs.org", "packages"),
                          ("virustotal.com", "security")):
            _m, _p, f2 = scan_text(f"203.0.113.9 {name}\n")
            check(f"a redirected {cat} name is critical",
                  any(x["severity"] == "critical" and name in x["title"] for x in f2),
                  [x["title"] for x in f2])
        _m, _p, f3 = scan_text("192.168.1.9 staging.internal\n")
        check("a private redirect of an unknown name is only low",
              not any(x["severity"] in ("critical", "high") for x in f3),
              [(x["title"], x["severity"]) for x in f3])
        _m, _p, f4d = scan_text("203.0.113.9 doc.example\n")
        check("a documentation address is named as such, not called private",
              any("documentation" in (e["scope"] or "")
                  for e in _p["entries"]), [e["scope"] for e in _p["entries"]])
        _m, _p, f4 = scan_text("8.8.8.8 whatever.example\n")
        check("a public redirect of an unknown name is medium",
              any(x["severity"] == "medium" for x in f4),
              [(x["title"], x["severity"]) for x in f4])

        print("\n Blocking what should not be blocked")
        _m, _p, f = scan_text("0.0.0.0 virustotal.com\n0.0.0.0 windowsupdate.com\n")
        check("blocking security and update services is HIGH",
              sum(1 for x in f if x["severity"] == "high") >= 2,
              [(x["title"], x["severity"]) for x in f])
        check("and the advice gives both explanations",
              any("oldest tricks" in x.get("advice", "") for x in f))
        _m, _p, f = scan_text("0.0.0.0 facebook.com\n")
        check("blocking a platform alone is not alarming",
              not any(x["severity"] in ("critical", "high") for x in f),
              [(x["title"], x["severity"]) for x in f])

        print("\n Deception and structure")
        _m, _p, f = scan_text("203.0.113.5 xn--80ak6aa92e.com\n")
        check("a confusable redirect is CRITICAL",
              any(x["severity"] == "critical" and "Latin" in x["title"] for x in f),
              [x["title"] for x in f])
        _m, _p, f = scan_text("127.0.0.1 a.example.com\n203.0.113.5 a.example.com\n")
        check("a shadowed entry pointing elsewhere is MEDIUM",
              any(x["severity"] == "medium" and "shadowed" in x["title"] for x in f),
              [(x["title"], x["severity"]) for x in f])
        check("and it names the line that actually wins",
              any("overridden by line 1" in x["evidence"] for x in f))
        _m, _p, f = scan_text("127.0.0.1\tlocalhost   \n")
        check("tabs and trailing whitespace are reported",
              any("whitespace" in x["title"] for x in f), [x["title"] for x in f])
        _m, _p, f = scan_text("127.0.0.1 localhost\n224.0.0.9 odd.example\n")
        check("a multicast address is reported as unusual",
              any("unusual address" in x["title"] for x in f), [x["title"] for x in f])
        _m, _p, f = scan_text("203.0.113.1 nolocalhost.example\n")
        check("a missing localhost entry is noted",
              any("no localhost" in x["title"] for x in f), [x["title"] for x in f])

        print("\n Permissions")
        p = _write(os.path.join(tmp, "ww_hosts"), "127.0.0.1 localhost\n")
        os.chmod(p, 0o666)
        meta = read_hosts(p)
        check("a world-writable file is detected", meta["world_writable"])
        f = analyse(meta, parse_hosts(meta["text"]), {})
        check("and reported as CRITICAL before anything else",
              f and f[0]["severity"] == "critical" and "world-writable" in f[0]["title"],
              [x["title"] for x in f])
        os.chmod(p, 0o644)
        check("a normal mode is not flagged", not read_hosts(p)["world_writable"])

        print("\n Approval quietens a finding")
        text = "127.0.0.1 localhost\n203.0.113.66 paypal.com\n"
        _m, _p, f_before = scan_text(text)
        _m, _p, f_after = scan_text(text, {"203.0.113.66 paypal.com": {}})
        check("approving an entry removes its finding",
              any(x["severity"] == "critical" for x in f_before)
              and not any(x["severity"] == "critical" for x in f_after),
              [(x["title"], x["severity"]) for x in f_after])
        check("and the approval is acknowledged",
              any("approved" in x["title"] for x in f_after))
        check("the score drops", risk_score(f_after) < risk_score(f_before))

        print("\n Change detection")
        old = [{"address": "127.0.0.1", "normalised": "localhost", "kind": "block",
                "category": None, "line": 1}]
        new = [{"address": "127.0.0.1", "normalised": "localhost", "kind": "block",
                "category": None, "line": 1},
               {"address": "203.0.113.66", "normalised": "paypal.com", "kind": "redirect",
                "category": "banking", "line": 2}]
        ch = diff_entries(old, new)
        check("an added entry is detected",
              [c["kind"] for c in ch] == ["added"], ch)
        check("nothing changes when nothing changed", diff_entries(new, new) == [])
        check("a removed entry is detected",
              [c["kind"] for c in diff_entries(new, old)] == ["removed"])
        moved = [dict(new[0]),
                 {"address": "198.51.100.1", "normalised": "paypal.com",
                  "kind": "redirect", "category": "banking", "line": 2}]
        ch = diff_entries(new, moved)
        check("a name whose address moved is reported as changed, not add plus remove",
              [c["kind"] for c in ch] == ["changed"], ch)
        check("and it records where it used to point",
              ch[0]["previous_address"] == "203.0.113.66")
        cf = analyse_changes(diff_entries(old, new), {})
        check("a newly added redirect of a bank is critical",
              any(x["severity"] == "critical" for x in cf),
              [(x["title"], x["severity"]) for x in cf])
        check("and it points out the change needed admin access",
              any("level of access" in x["advice"] for x in cf))

        print("\n Persistence")
        init_db()
        target = _write(os.path.join(tmp, "hosts"),
                        "127.0.0.1 localhost\n203.0.113.5 x.example.com\n")
        sid, meta, parsed, changes, findings = run_scan(target, note="selftest")
        check("a scan is stored", scan_summary(sid) is not None)
        check("an observation is stored per entry",
              q1("SELECT COUNT(*) c FROM observations WHERE scan_id=?",
                 (sid,))["c"] == len(parsed["entries"]))
        check("findings are stored",
              q1("SELECT COUNT(*) c FROM findings WHERE scan_id=?",
                 (sid,))["c"] == len(findings))
        sid2, _m, _p, changes2, _f = run_scan(target)
        check("an unchanged file reports no changes", changes2 == [], changes2)
        check("the second scan links to the first",
              scan_summary(sid2)["prev_scan_id"] == sid)
        _write(target, "127.0.0.1 localhost\n203.0.113.66 paypal.com\n")
        sid3, _m, _p, changes3, findings3 = run_scan(target)
        check("an edited file produces changes", len(changes3) >= 1, changes3)
        check("the new redirect is reported",
              any(c["kind"] in ("added", "changed") for c in changes3), changes3)
        check("a redirect change is logged as a warning",
              q1("SELECT COUNT(*) c FROM audit_log WHERE level='WARN'", ())["c"] >= 1)
        key = approve_entry("203.0.113.66", "paypal.com")
        check("an entry can be approved", key in approved_map())
        check("approval can be revoked",
              revoke_entry("203.0.113.66", "paypal.com") == 1
              and key not in approved_map())

        print("\n Unreadable files")
        missing = read_hosts(os.path.join(tmp, "does-not-exist"))
        check("a missing file is reported, not crashed on", bool(missing["error"]))
        f = analyse(missing, {"entries": [], "unique_names": 0, "comments": 0,
                              "blank": 0, "malformed": [], "total_lines": 0}, {})
        check("and nothing is presented as clean",
              any("not checked" in x["advice"] for x in f), [x["title"] for x in f])

        print("\n Charts")
        parsed_fx = parse_hosts("127.0.0.1 localhost\n203.0.113.5 a.example.com\n")
        check("the split chart draws a row per kind",
              svg_split(parsed_fx).count("<rect") >= 4)
        check("the split chart with nothing says so", "no entries" in svg_split({}))
        rm = svg_redirect_map(parsed_fx, set())
        check("the redirect map draws a row per redirect", rm.count("<rect") >= 1)
        check("the redirect map says so when nothing is redirected",
              "nothing is redirected" in svg_redirect_map(
                  parse_hosts("127.0.0.1 localhost\n"), set()))
        check("pie renders slices",
              svg_pie([("a", 2, "#fff"), ("b", 1, "#000")]).count("<path") == 2)
        check("history needs two checks and says so",
              "needs at least two" in svg_history([{"entries": 3}]))
        check("history draws with enough points",
              "<path" in svg_history([{"entries": 3, "id": 1},
                                      {"entries": 4, "id": 2}]))
        check("every chart guards against empty input",
              all("nothing to show" in x or "needs at least" in x or "no " in x
                  for x in (svg_pie([]), svg_history([]), svg_split({}), svg_bar([]))))

        print("\n Exports")
        j = json.loads(export_json(sid3))
        check("JSON export carries the disclaimer", "READ-ONLY" in j["disclaimer"].upper())
        check("JSON export states blocking is ordinary",
              "Blocking is ordinary" in j["blocking_is_ordinary"])
        check("JSON export states it never writes", "never modified" in j["read_only"])
        check("JSON export lists the limitations", len(j["limitations"]) >= 5)
        check("JSON export says a clean hosts file is not a clean machine",
              any("resolver" in x for x in j["limitations"]))
        c_ = export_csv(sid3)
        check("CSV export has sections", c_.count("##") >= 3)
        check("CSV states the block-versus-redirect distinction",
              any("redirecting is what matters" in l for l in c_.splitlines()[:6]))
        h = export_html(sid3)
        check("HTML export is a complete document",
              h.startswith("<!doctype html") and h.rstrip().endswith("</html>"))
        check("HTML export contains charts and the author", "<svg" in h and AUTHOR in h)

        print("\n Web application")
        if not HAVE_FLASK:
            check("Flask installed", False, "pip install flask")
        else:
            app = build_app()
            app.config["TESTING"] = True
            cl = app.test_client()
            for path, must in (("/", "Overview"), ("/entries", "Entries"),
                               ("/changes", "Changes"), ("/learn", "before DNS")):
                r_ = cl.get(path)
                body = r_.get_data(as_text=True)
                check(f"page {path} renders",
                      r_.status_code == 200 and must.lower() in body.lower(), r_.status_code)
            check("every page carries the block-versus-redirect banner",
                  "Blocking is ordinary" in cl.get("/").get_data(as_text=True))
            check("the learn page explains the distinction",
                  "goes nowhere" in cl.get("/learn").get_data(as_text=True))
            n0 = q1("SELECT COUNT(*) c FROM scans", ())["c"]
            r_ = cl.post("/scan", data={"path": target})
            check("a check runs from the web",
                  r_.status_code == 302
                  and q1("SELECT COUNT(*) c FROM scans", ())["c"] == n0 + 1)
            r_ = cl.post("/approve", data={"address": "203.0.113.66",
                                           "name": "paypal.com"})
            check("approving from the web works",
                  r_.status_code == 302
                  and "203.0.113.66 paypal.com" in approved_map())
            r_ = cl.post("/revoke", data={"address": "203.0.113.66",
                                          "name": "paypal.com"})
            check("revoking from the web works",
                  r_.status_code == 302
                  and "203.0.113.66 paypal.com" not in approved_map())
            check("entry filters apply",
                  cl.get("/entries?kind=redirect&qq=example").status_code == 200)
            for fmt, ctype in (("json", "application/json"), ("csv", "text/csv"),
                               ("html", "text/html")):
                r_ = cl.get(f"/export/{fmt}?scan={sid3}")
                check(f"export /{fmt} downloads",
                      r_.status_code == 200 and ctype in r_.headers["Content-Type"]
                      and "attachment" in r_.headers.get("Content-Disposition", ""))
            check("bad export format is rejected", cl.get("/export/exe").status_code == 400)
            check("unknown route returns a helpful 404", cl.get("/nope").status_code == 404)
            api = cl.get("/api/summary").get_json()
            check("the api declares it is read-only", api["read_only"] is True)
            check("the api declares it sees only this file",
                  api["sees_only_this_file"] is True)

        print("\n It never writes to the hosts file")
        before = hashlib.sha256(open(target, "rb").read()).hexdigest()
        mtime = os.path.getmtime(target)
        run_scan(target)
        after = hashlib.sha256(open(target, "rb").read()).hexdigest()
        check("the file's bytes are unchanged after a scan", before == after)
        check("the file's modification time is unchanged",
              os.path.getmtime(target) == mtime)
        mod = sys.modules[__name__]
        check("no function in this module writes a hosts file",
              not any(n.startswith(("write_hosts", "clean_hosts", "fix_hosts",
                                    "restore_hosts", "repair"))
                      for n in dir(mod)),
              [n for n in dir(mod) if "hosts" in n and n.startswith(("write", "fix"))])
        check("no CLI command offers to edit it",
              not any(n in ("cmd_fix", "cmd_clean", "cmd_restore", "cmd_repair")
                      for n in dir(mod)))

        print("\n Retention")
        cmd_purge(argparse.Namespace(all=False, keep=1, approved=False))
        check("purge keeps exactly the newest scan",
              q1("SELECT COUNT(*) c FROM scans", ())["c"] == 1)
        check("purge removes orphaned rows",
              all(q1(f"SELECT COUNT(*) c FROM {t} WHERE scan_id NOT IN "
                     f"(SELECT id FROM scans)", ())["c"] == 0
                  for t in ("observations", "changes", "findings")))
        approve_entry("1.2.3.4", "keep.example")
        cmd_purge(argparse.Namespace(all=True, keep=1, approved=False))
        check("purge --all clears the scans",
              q1("SELECT COUNT(*) c FROM scans", ())["c"] == 0)
        check("approvals survive by default", len(approved_map()) > 0)
        cmd_purge(argparse.Namespace(all=True, keep=1, approved=True))
        check("purge --all --approved clears them too", len(approved_map()) == 0)
    finally:
        set_db_path(original)
        shutil.rmtree(tmp, ignore_errors=True)

    line("=")
    print(f"  {len(passed)} passed, {len(failed)} failed")
    if failed:
        print("  Failed: " + ", ".join(failed))
    else:
        print("  All checks passed. No hosts file was modified and the temporary database\n"
              "  and fixtures have been removed.")
    line("=")
    return 0 if not failed else 1


# =============================================================================
# SECTION 11 - Entry point
# =============================================================================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=os.path.basename(__file__),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=f"{APP_NAME} v{VERSION} - hosts file tampering detector, by {AUTHOR}",
        epilog=textwrap.dedent(f"""\
            examples
              %(prog)s learn                  why the hosts file matters
              %(prog)s check
              %(prog)s check --path ./hosts --verbose
              %(prog)s watch --interval 300
              %(prog)s entries --redirects-only
              %(prog)s approve 192.168.1.9 staging.internal
              %(prog)s check --fail-on-redirect
              %(prog)s serve

            Read-only. There is deliberately no command that edits the hosts file.

            {DISCLAIMER_LONG}
            """))
    p.add_argument("--db", default=DEFAULT_DB,
                   help=f"SQLite database file (default: {DEFAULT_DB}, env HOSTSGUARD_DB)")
    p.add_argument("--version", action="version", version=f"{APP_NAME} {VERSION}")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("check", help="read and check the hosts file")
    s.add_argument("--path", help="a hosts file to check instead of the system one")
    s.add_argument("--quiet", action="store_true", help="hide informational findings")
    s.add_argument("--show", type=int, help="limit how many findings are printed")
    s.add_argument("--limit", type=int, default=20)
    s.add_argument("--fail-on-redirect", action="store_true",
                   help="exit non-zero if a sensitive name is redirected, for monitoring")
    s.add_argument("--fail-over", type=float, help="exit non-zero above this score")
    s.add_argument("--note")
    s.set_defaults(func=cmd_check)

    s = sub.add_parser("watch", help="check repeatedly and report only what changes")
    s.add_argument("--path")
    s.add_argument("--interval", type=float, default=300.0)
    s.add_argument("--count", type=int)
    s.add_argument("--quiet", action="store_true")
    s.set_defaults(func=cmd_watch)

    s = sub.add_parser("entries", help="list entries from the latest check")
    s.add_argument("--redirects-only", action="store_true")
    s.add_argument("--name")
    s.add_argument("--limit", type=int, default=100)
    s.set_defaults(func=cmd_entries)

    s = sub.add_parser("approve", help="mark an entry as expected")
    s.add_argument("address")
    s.add_argument("name")
    s.add_argument("--note")
    s.set_defaults(func=cmd_approve)

    s = sub.add_parser("revoke", help="remove an approval")
    s.add_argument("address")
    s.add_argument("name")
    s.set_defaults(func=cmd_revoke)

    s = sub.add_parser("learn", help="why the hosts file matters, and what this cannot see")
    s.set_defaults(func=cmd_learn)

    s = sub.add_parser("scans", help="list previous checks")
    s.add_argument("--limit", type=int, default=25)
    s.set_defaults(func=cmd_scans)

    s = sub.add_parser("serve", help="start the web app")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=5000)
    s.add_argument("--debug", action="store_true")
    s.set_defaults(func=cmd_serve)

    s = sub.add_parser("export", help="write a report to a file")
    s.add_argument("--scan", type=int)
    s.add_argument("--format", choices=["json", "csv", "html"], default="html")
    s.add_argument("--out")
    s.set_defaults(func=cmd_export)

    s = sub.add_parser("logs", help="local event log")
    s.add_argument("--level", choices=["INFO", "WARN", "ERROR", "info", "warn", "error"])
    s.add_argument("--limit", type=int, default=50)
    s.set_defaults(func=cmd_logs)

    s = sub.add_parser("purge", help="delete stored checks")
    s.add_argument("--keep", type=int, default=50)
    s.add_argument("--all", action="store_true")
    s.add_argument("--approved", action="store_true",
                   help="with --all, also clear approvals")
    s.set_defaults(func=cmd_purge)

    s = sub.add_parser("selftest", help="verify every component (temporary database)")
    s.set_defaults(func=cmd_selftest)

    s = sub.add_parser("version", help="versions and the disclaimer")
    s.set_defaults(func=cmd_version)
    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    set_db_path(args.db)
    if not getattr(args, "cmd", None):
        parser.print_help()
        return 0
    if args.cmd != "selftest":
        init_db()
    try:
        rc = args.func(args)
        return rc if isinstance(rc, int) else 0
    except BrokenPipeError:
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except Exception:
            pass
        return 0
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130
    except PermissionError as e:
        print(f"Permission denied: {e}")
        return 1
    except sqlite3.OperationalError as e:
        print(f"Database error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
