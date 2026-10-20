"""Builds a fake user profile full of bait data (honeytokens).

Every secret contains a unique marker (ANLT-xxxxxxxx). If a marker shows up in
the sandbox trace, we know the program read or tried to send that data.
All values are generated. Nothing here is real.
"""
import json
import random
import secrets
import sqlite3
from pathlib import Path

FAKE_SITES = ["mail.example-bank.test", "social.example.test", "shop.example.test",
              "game.example.test", "cloud.example.test"]


def _marker() -> str:
    return "ANLT-" + secrets.token_hex(4)


def build(home: Path) -> dict:
    """Creates the fake profile in `home`. Returns {marker: description}."""
    markers = {}
    rnd = random.Random(secrets.token_hex(8))

    # Fake Chrome login database
    chrome = home / ".config" / "google-chrome" / "Default"
    chrome.mkdir(parents=True)
    db = sqlite3.connect(chrome / "Login Data")
    db.execute("CREATE TABLE logins (origin_url TEXT, username_value TEXT, password_value TEXT)")
    for site in FAKE_SITES:
        m = _marker()
        user = f"user{rnd.randint(100, 999)}@example.test"
        db.execute("INSERT INTO logins VALUES (?,?,?)", (f"https://{site}", user, f"pw-{m}"))
        markers[m] = f"saved browser password for {site}"
    db.commit()
    db.close()

    # Fake cookies
    m = _marker()
    (chrome / "Cookies").write_text(f"session_id={m}; domain=social.example.test\n")
    markers[m] = "browser session cookie"

    # Fake Discord token
    discord = home / ".config" / "discord" / "Local Storage" / "leveldb"
    discord.mkdir(parents=True)
    m = _marker()
    (discord / "000003.log").write_text(f'"token":"{m}.fakefakefake.notarealtoken"\n')
    markers[m] = "Discord login token"

    # Fake crypto wallet
    wallet = home / ".config" / "Exodus" / "exodus.wallet"
    wallet.mkdir(parents=True)
    m = _marker()
    (wallet / "seed.seco").write_text(f"seed phrase: abandon ability {m}\n")
    markers[m] = "crypto wallet seed phrase"

    # Fake ssh key
    ssh = home / ".ssh"
    ssh.mkdir()
    m = _marker()
    (ssh / "id_rsa").write_text(f"-----BEGIN FAKE KEY-----\n{m}\n-----END FAKE KEY-----\n")
    markers[m] = "SSH private key"

    # Bait documents
    docs = home / "Documents"
    docs.mkdir()
    m = _marker()
    (docs / "sifreler.txt").write_text(f"banka: 1234\nemail sifre: {m}\n")
    markers[m] = "passwords text file (sifreler.txt)"
    (home / ".bash_history").write_text("ls\ncd Documents\nssh fake@example.test\n")

    (home / ".anlat-markers.json").write_text(json.dumps(markers))
    return markers


def meminfo(gb: int = 16) -> str:
    kb = gb * 1024 * 1024
    return (f"MemTotal:       {kb} kB\nMemFree:        {kb // 2} kB\n"
            f"MemAvailable:   {int(kb * 0.6)} kB\nBuffers:        {kb // 40} kB\n"
            f"Cached:         {kb // 5} kB\nSwapTotal:      {kb // 4} kB\nSwapFree:       {kb // 4} kB\n")
