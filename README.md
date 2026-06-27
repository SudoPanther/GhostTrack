<div align="center">

# 👻 GhostTrack

### Interactive CLI OSINT Username Reconnaissance Tool

Find where a username is registered across **40+ major platforms** — GitHub, Reddit, Instagram, Steam, Twitch, TikTok, and many more — from a single interactive terminal.

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)]()
[![Maintained](https://img.shields.io/badge/maintained-yes-brightgreen.svg)]()
[![Author](https://img.shields.io/badge/author-%40Sudopanther-orange.svg)](https://github.com/Sudopanther)

</div>

<br>

---

## ⚠️ Legal & Ethical Use Disclaimer

> GhostTrack is built for **educational purposes, authorized penetration testing, and ethical OSINT research only**. Running reconnaissance against accounts or identities you do not own or do not have explicit authorization to investigate may violate platform Terms of Service and, depending on your jurisdiction, the law. The author assumes no liability for misuse. **Use responsibly.**

---

## 📖 Overview

GhostTrack is a single-file, dependency-light Python tool that checks whether a given username exists across a large, configurable database of online platforms. It runs as an **interactive REPL** rather than a one-shot CLI script — set a target once, then scan, filter, save aliases, and export results without re-typing flags every time.

It ships with **42 pre-configured platforms** out of the box and a fully extensible site database stored as JSON, so you can add, remove, or tag your own targets.

---

## ✨ Features

- 🔍 **40+ built-in OSINT targets** — GitHub, GitLab, Bitbucket, Reddit, Dev.to, Twitter/X, Instagram, Medium, Steam, Behance, Pinterest, HackerNews, Roblox, Twitch, Spotify, SoundCloud, Vimeo, Scribd, SlideShare, ProductHunt, Keybase, Dribbble, TikTok, Facebook, Telegram, VK, Quora, Tumblr, Flickr, DeviantArt, Gravatar, Kaggle, PyPI, NPM, CodePen, and more
- 🧠 **Interactive command shell** with persistent session state (active target, last results)
- 🏷️ **Tag-based filtering** — scan only `social`, `gaming`, `tech`, `dev`, etc.
- 📁 **Custom site groups (aliases)** for quickly re-running the same subset of sites
- ➕ **Extensible site database** — add or remove platforms without touching code
- ⚡ **Fully asynchronous scanning** (`asyncio` + `aiohttp`) with bounded concurrency
- 🛡️ **Robust error handling** — timeouts and network failures never crash the tool
- 💾 **Export results** to CSV or JSON
- 🎨 **Color-coded terminal output** via `colorama`
- 🧷 **Graceful Ctrl+C / Ctrl+D handling** — no messy tracebacks, ever

---

## 🛠️ Installation

### Requirements

- Python **3.8+**
- `aiohttp`
- `colorama`

### Setup

```bash
# Clone the repository
git clone https://github.com/Sudopanther/ghosttrack.git
cd ghosttrack

# Install dependencies
pip install aiohttp colorama

# Run it
python ghosttrack.py
```

> 💡 On first launch, GhostTrack automatically creates `~/.ghosttrack/sites.json` pre-loaded with 42 default platforms — no manual setup required.

---

## 🚀 Quick Start

```bash
$ python ghosttrack.py

ghosttrack(no-target)> target johndoe123
[+] Active target set to 'johndoe123'.

ghosttrack(johndoe123)> scan --tag dev
[*] Scanning 7 site(s) for target 'johndoe123'...

  [FOUND]     GitHub               https://github.com/johndoe123
  [not found] GitLab               https://gitlab.com/johndoe123
  ...

[+] Scan complete: 3 found, 4 not found, 0 errors/timeouts.

ghosttrack(johndoe123)> export csv
[+] Exported 7 result(s) to ~/.ghosttrack/results/johndoe123_1719500000.csv
```

---

## 📋 Command Reference

### 🎯 Target Management

| Command | Description |
|---|---|
| `target <username>` | Set the active username to investigate |

### 🔎 Scanning

| Command | Description |
|---|---|
| `scan` | Scan **all** enabled sites against the active target |
| `scan --tag <category>` | Scan only sites matching a tag (e.g. `social`, `gaming`, `tech`) |
| `scan --sites <site1,site2,...>` | Scan only the exact comma-separated site names |
| `scan --alias <name>` | Scan only the sites saved under a given alias |

### 🗄️ Site Database

| Command | Description |
|---|---|
| `addsite <name> <url_with_{}> <error_type> <error_value> [tags]` | Add a new site to the database |
| `removesite <name>` | Remove a site by exact name |
| `list sites` | List every site in the database, with tags and status |
| `list tags` | List every distinct tag currently in use |

**`error_type` values for `addsite`:**

| Type | `error_value` meaning |
|---|---|
| `status_code` | HTTP status code returned for a missing profile (e.g. `404`) |
| `message` | Text snippet present in the page body when the profile is missing |
| `response_url` | URL fragment the user is redirected to when the profile is missing |

```bash
addsite MySite https://mysite.com/{} status_code 404 social,custom
```

### 🏷️ Aliases

| Command | Description |
|---|---|
| `alias create <name> <site1,site2,...>` | Save a named group of sites for quick re-use |
| `alias list` | Show all saved aliases and their member sites |
| `alias delete <name>` | Delete a saved alias |

### 📤 Results & Export

| Command | Description |
|---|---|
| `results` | Re-print the results from the most recent scan |
| `export <csv\|json> [filename]` | Export the most recent scan results to a file |

### ⚙️ Misc

| Command | Description |
|---|---|
| `clear` | Clear the terminal screen |
| `help` | Show the full in-terminal command reference |
| `exit` / `quit` | Exit GhostTrack |

> Press **Ctrl+C** or **Ctrl+D** at any time — GhostTrack intercepts both and shuts down cleanly instead of throwing a traceback.

---

## 🧩 Example Workflows

**Scan everything:**
```bash
ghosttrack(no-target)> target jdoe
ghosttrack(jdoe)> scan
```

**Scan only gaming platforms:**
```bash
ghosttrack(jdoe)> scan --tag gaming
```

**Scan a specific shortlist:**
```bash
ghosttrack(jdoe)> scan --sites GitHub,GitLab,Dev.to
```

**Build and reuse a custom group:**
```bash
ghosttrack(jdoe)> alias create devstack GitHub,GitLab,Dev.to,Keybase,PyPI
ghosttrack(jdoe)> scan --alias devstack
```

**Export findings for a report:**
```bash
ghosttrack(jdoe)> export json jdoe_recon
ghosttrack(jdoe)> export csv jdoe_recon
```

---

## 📂 Project Structure

```
~/.ghosttrack/
├── sites.json          # Site database 
├── aliases.json        # Saved alias groups
└── results/            # Exported CSV/JSON scan results
```

---

## ⚠️ A Note on Accuracy

Websites change their HTTP status codes, redirect behavior, and "not found" page content over time without notice. The default site signatures are accurate as of authoring, but **OSINT username-checkers are inherently subject to drift** — this is true of every tool in this category (Sherlock, Maigret, etc.), not a flaw unique to GhostTrack. If a result looks wrong, verify manually and feel free to open an issue or PR with a fix.

---

## 🤝 Contributing

Contributions are welcome! If you'd like to add a new default site, fix a broken signature, or add a feature:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-site`)
3. Commit your changes
4. Open a Pull Request

---

## 📜 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**[@Sudopanther](https://github.com/Sudopanther)**

If you found this tool useful, consider ⭐ starring the repository!
