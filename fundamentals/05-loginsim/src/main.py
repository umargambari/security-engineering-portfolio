#!/usr/bin/env python3
"""Login Simulator — mock authentication with hashing, lockout, and session tracking."""

import argparse
import getpass
import json
import os
import sys
from datetime import datetime, timezone

import bcrypt


USER_DB_PATH = "users.json"
MAX_FAILED_ATTEMPTS = 5


def load_users(db_path: str = USER_DB_PATH) -> dict:
    """Load the user database from a JSON file."""
    if not os.path.exists(db_path):
        return {}
    try:
        with open(db_path, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return {}


def save_users(users: dict, db_path: str = USER_DB_PATH) -> None:
    """Save the user database to a JSON file."""
    with open(db_path, "w") as f:
        json.dump(users, f, indent=2)


def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against a bcrypt hash."""
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))


def register_user(username: str, password: str, db_path: str = USER_DB_PATH) -> bool:
    """Register a new user."""
    users = load_users(db_path)
    if username in users:
        return False

    users[username] = {
        "password_hash": hash_password(password),
        "failed_attempts": 0,
        "locked": False,
        "login_history": [],
    }
    save_users(users, db_path)
    return True


def login_user(username: str, password: str, db_path: str = USER_DB_PATH) -> dict:
    """Attempt to log in a user."""
    users = load_users(db_path)

    if username not in users:
        return {"success": False, "message": "User not found"}

    user = users[username]
    timestamp = datetime.now(timezone.utc).isoformat()

    if user["locked"]:
        user["login_history"].append({
            "timestamp": timestamp, "success": False, "reason": "account locked"
        })
        save_users(users, db_path)
        return {"success": False, "message": "Account is locked"}

    if verify_password(password, user["password_hash"]):
        user["failed_attempts"] = 0
        user["login_history"].append({"timestamp": timestamp, "success": True})
        save_users(users, db_path)
        return {"success": True, "message": "Login successful"}
    else:
        user["failed_attempts"] += 1
        user["login_history"].append({"timestamp": timestamp, "success": False})
        if user["failed_attempts"] >= MAX_FAILED_ATTEMPTS:
            user["locked"] = True
        save_users(users, db_path)
        message = "Invalid password"
        if user["locked"]:
            message += " -- account is now locked"
        return {"success": False, "message": message}


def get_user_status(username: str, db_path: str = USER_DB_PATH) -> dict | None:
    """Get the status of a user account."""
    users = load_users(db_path)
    if username not in users:
        return None
    user = users[username]
    return {
        "username": username,
        "locked": user["locked"],
        "failed_attempts": user["failed_attempts"],
        "login_history": user["login_history"],
    }


def cmd_register(args: argparse.Namespace) -> None:
    """Handle the 'register' subcommand."""
    password = getpass.getpass("Password: ")
    success = register_user(args.username, password)
    if success:
        print(f"User '{args.username}' registered successfully")
    else:
        print(f"Error: username '{args.username}' already exists", file=sys.stderr)
        sys.exit(1)


def cmd_login(args: argparse.Namespace) -> None:
    """Handle the 'login' subcommand."""
    password = getpass.getpass("Password: ")
    result = login_user(args.username, password)
    print(result["message"])
    sys.exit(0 if result["success"] else 1)


def cmd_status(args: argparse.Namespace) -> None:
    """Handle the 'status' subcommand."""
    status = get_user_status(args.username)
    if status is None:
        print(f"User '{args.username}' not found")
        return
    print(f"Username: {status['username']}")
    print(f"Locked: {status['locked']}")
    print(f"Failed attempts: {status['failed_attempts']}")
    print(f"Login history ({len(status['login_history'])} entries):")
    for entry in status["login_history"][-5:]:
        outcome = "SUCCESS" if entry["success"] else "FAILED"
        print(f"  {entry['timestamp']}  {outcome}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="loginsim",
        description="Mock authentication system with hashing and lockout.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    register_parser = subparsers.add_parser("register", help="Register a new user")
    register_parser.add_argument("username", help="Username to register")
    register_parser.set_defaults(func=cmd_register)

    login_parser = subparsers.add_parser("login", help="Log in as a user")
    login_parser.add_argument("username", help="Username to log in as")
    login_parser.set_defaults(func=cmd_login)

    status_parser = subparsers.add_parser("status", help="Show account status")
    status_parser.add_argument("username", help="Username to check")
    status_parser.set_defaults(func=cmd_status)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
