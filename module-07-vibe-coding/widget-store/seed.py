#!/usr/bin/env python3
"""Builds the store database both halves of the lab read.

One schema, two population modes. The weak app gets plaintext passwords
because that is what the generation wrote. The hardened app gets PBKDF2
hashes because that is what the control map demanded. Same users, same
widgets, same orders, so every attack you run against one has an exact
counterpart to run against the other.

    python3 seed.py weak/store.db --plaintext
    python3 seed.py hardened/store.db --hashed
"""
import hashlib
import hmac
import os
import sqlite3
import sys

USERS = [
    # id, username, password, role
    (1, "alice", "alice123", "user"),
    (2, "bob", "hunter2", "user"),
    (3, "root", "Widget$Admin!2026", "admin"),
]

WIDGETS = [
    (1, "Alpha Widget", 24.00, "General purpose. The one most people should buy."),
    (2, "Beta Widget", 39.50, "Higher tolerance. Worth it if you are mounting it."),
    (3, "Gamma Widget", 58.00, "Sealed housing. Holds up outdoors and in wash-down areas."),
    (4, "Delta Widget", 112.75, "Industrial. Overkill for a workshop, correct for a plant."),
]

ORDERS = [
    (1001, "Alpha Widget", 24.00, "alice"),
    (1002, "Gamma Widget", 58.00, "bob"),
    (1003, "Delta Widget", 112.75, "root"),
]

SCHEMA = """
CREATE TABLE users   (id INTEGER PRIMARY KEY, username TEXT UNIQUE,
                      password TEXT, role TEXT);
CREATE TABLE widgets (id INTEGER PRIMARY KEY, name TEXT, price REAL,
                      blurb TEXT, list_price REAL);
CREATE TABLE reviews (id INTEGER PRIMARY KEY AUTOINCREMENT, widget_id INTEGER,
                      author TEXT, body TEXT);
CREATE TABLE orders  (id INTEGER PRIMARY KEY, item TEXT, total REAL, buyer TEXT);
CREATE TABLE modelog (id INTEGER PRIMARY KEY AUTOINCREMENT, who TEXT,
                      question TEXT, answer TEXT, flagged TEXT);
"""


def pbkdf2(password: str, salt: bytes) -> str:
    """Deliberately boring. 240k rounds of SHA-256, salt stored alongside.

    Not the strongest option available, and the point is not that it is the
    strongest. The point is that the weak app has nothing here at all, and
    the gap between nothing and this is the whole of the finding."""
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 240_000)
    return "pbkdf2_sha256$240000$" + salt.hex() + "$" + dk.hex()


def verify(password: str, stored: str) -> bool:
    """Constant-time compare, and it returns False rather than raising on a
    row that is not a hash at all. An account seeded before hashing existed
    should fail to sign in, not crash the login route."""
    try:
        algo, rounds, salt_hex, want = stored.split("$")
    except ValueError:
        return False
    if algo != "pbkdf2_sha256":
        return False
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(),
                             bytes.fromhex(salt_hex), int(rounds))
    return hmac.compare_digest(dk.hex(), want)


def build(path: str, hashed: bool) -> None:
    if os.path.exists(path):
        os.remove(path)
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    c = sqlite3.connect(path)
    c.executescript(SCHEMA)
    for uid, name, pw, role in USERS:
        stored = pbkdf2(pw, os.urandom(16)) if hashed else pw
        c.execute("INSERT INTO users VALUES (?,?,?,?)", (uid, name, stored, role))
    for wid, name, price, blurb in WIDGETS:
        # list_price is the column the hardened app prices from. The weak app
        # never reads it, which is why the chatbot can move the price at all.
        c.execute("INSERT INTO widgets VALUES (?,?,?,?,?)",
                  (wid, name, price, blurb, price))
    for oid, item, total, buyer in ORDERS:
        c.execute("INSERT INTO orders VALUES (?,?,?,?)", (oid, item, total, buyer))
    c.execute("INSERT INTO reviews (widget_id, author, body) VALUES (?,?,?)",
              (1, "alice", "Does the job. Arrived in two days."))
    c.commit()
    c.close()
    print("built %s (%s passwords)" % (path, "hashed" if hashed else "PLAINTEXT"))


if __name__ == "__main__":
    args = sys.argv[1:]
    if not args:
        here = os.path.dirname(os.path.abspath(__file__))
        build(os.path.join(here, "weak", "store.db"), hashed=False)
        build(os.path.join(here, "hardened", "store.db"), hashed=True)
    else:
        build(args[0], hashed="--hashed" in args)
