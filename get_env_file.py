#!/usr/bin/env python3
"""
convert_twitter_format.py

Reads a pipe-delimited file with lines:
    username|password|email|email_password|proxy

Outputs three environment-style lines:
    TWITTER_ACCOUNTS="user1:pass1,user2:pass2,..."
    TWITTER_EMAIL="email1+email2+..."
    TWITTER_EMAIL_PASSWORD="epass1+epass2+..."
"""

import argparse
import sys
from typing import List

def escape_double_quotes(s: str) -> str:
    """Escape double quotes for safe inclusion inside a double-quoted string."""
    return s.replace('"', '\\"')

def process_lines(lines: List[str]):
    accounts = []
    emails = []
    email_passwords = []
    malformed = 0

    for lineno, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line:
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 5:
            # tolerant: if fewer than 5 parts, consider it malformed but attempt to salvage
            malformed += 1
            print(f"Warning: line {lineno} is malformed (expected 5 fields): {line}", file=sys.stderr)
            # try to continue with whatever is present
            while len(parts) < 5:
                parts.append("")  # pad missing fields with empty string

        username, password, email, email_password, _proxy = parts[:5]

        # Only add account if username and password exist
        if username and password:
            accounts.append(f"{username}:{password}")
        else:
            print(f"Warning: line {lineno} missing username or password, skipped account entry.", file=sys.stderr)

        # Add email if present
        if email:
            emails.append(email)
        else:
            print(f"Warning: line {lineno} missing email, skipped email entry.", file=sys.stderr)

        # Add email password if present
        if email_password:
            email_passwords.append(email_password)
        else:
            print(f"Warning: line {lineno} missing email password, skipped email password entry.", file=sys.stderr)

    # Build final strings, escaping any internal double quotes
    accounts_str = ",".join(accounts)
    emails_str = "+".join(emails)
    email_passwords_str = "+".join(email_passwords)

    accounts_str = escape_double_quotes(accounts_str)
    emails_str = escape_double_quotes(emails_str)
    email_passwords_str = escape_double_quotes(email_passwords_str)

    tw_accounts = f'TWITTER_ACCOUNTS="{accounts_str}"'
    tw_emails = f'TWITTER_EMAIL="{emails_str}"'
    tw_email_pw = f'TWITTER_EMAIL_PASSWORD="{email_passwords_str}"'

    return tw_accounts, tw_emails, tw_email_pw, malformed

def main():
    p = argparse.ArgumentParser(description="Convert pipe-delimited twitter account lines into TWITTER_* env lines.")
    p.add_argument("-i", "--input", help="Input file path (default: stdin)", default=None)
    p.add_argument("-o", "--output", help="Output file path (default: stdout)", default=None)
    args = p.parse_args()

    # Read input
    if args.input:
        try:
            with open(args.input, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except Exception as e:
            print(f"Error reading input file {args.input}: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print("Reading from stdin. Enter lines then EOF (Ctrl-D on Unix / Ctrl-Z Enter on Windows).", file=sys.stderr)
        lines = sys.stdin.read().splitlines()

    tw_accounts, tw_emails, tw_email_pw, malformed = process_lines(lines)

    output_lines = [tw_accounts, tw_emails, tw_email_pw]
    output_text = "\n".join(output_lines) + "\n"

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output_text)
            print(f"Wrote output to {args.output}", file=sys.stderr)
        except Exception as e:
            print(f"Error writing output file {args.output}: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        # print to stdout
        print(output_text, end="")

    if malformed:
        print(f"Finished with {malformed} malformed line(s). See warnings above.", file=sys.stderr)

if __name__ == "__main__":
    main()
