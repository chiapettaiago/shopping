#!/usr/bin/env python3
"""Utility to toggle the admin flag for a user in the local SQLite database."""

import argparse
import sqlite3
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Set or remove the admin flag for a user in the shopping app database."
    )
    parser.add_argument("username", help="Username to update.")
    parser.add_argument(
        "--db",
        default="instance/database.db",
        help="Path to the SQLite database (default: instance/database.db).",
    )
    admin_group = parser.add_mutually_exclusive_group()
    admin_group.add_argument(
        "--set",
        dest="admin",
        action="store_true",
        help="Grant admin access to the user (default).",
    )
    admin_group.add_argument(
        "--unset",
        dest="admin",
        action="store_false",
        help="Revoke admin access from the user.",
    )
    parser.set_defaults(admin=True)
    return parser.parse_args()


def ensure_db_exists(db_path: Path) -> None:
    if not db_path.exists():
        raise FileNotFoundError(f"Database not found: {db_path}")


def update_admin_flag(db_path: Path, username: str, admin: bool) -> bool:
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT id, username, is_admin FROM user WHERE username = ?", (username,))
        row = cur.fetchone()
        if row is None:
            raise LookupError(f"User not found: {username}")
        cur.execute("UPDATE user SET is_admin = ? WHERE id = ?", (1 if admin else 0, row["id"]))
        conn.commit()
        return bool(cur.rowcount)


def fetch_current_status(db_path: Path, username: str) -> bool:
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT is_admin FROM user WHERE username = ?", (username,))
        row = cur.fetchone()
        if row is None:
            raise LookupError(f"User not found: {username}")
        return bool(row["is_admin"])


def main() -> int:
    args = parse_args()
    db_path = Path(args.db)
    try:
        ensure_db_exists(db_path)
        update_admin_flag(db_path, args.username, args.admin)
        status = fetch_current_status(db_path, args.username)
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except LookupError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except sqlite3.DatabaseError as exc:
        print(f"Database error: {exc}", file=sys.stderr)
        return 3

    state = "admin" if status else "regular user"
    print(f"User '{args.username}' is now marked as {state} in {db_path}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
