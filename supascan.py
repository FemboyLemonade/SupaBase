import argparse
import base64
import getpass
import json
import os
import sys
import warnings

from pathlib import Path
from typing import Optional

import requests

from pystyle import Colors, Write

from discover import SupabaseDiscovery
from extraction import SupabaseExtraction
from utility.logger import Logger

warnings.filterwarnings("ignore", category = Warning)

CONFIG_DIR = Path(__file__).resolve().parent / "config"


def decode_session_cookie(value: str) -> str:

    """
    Extract the access token from a Supabase auth cookie value
    (sb-<ref>-auth-token), which is JSON or base64-encoded JSON.
    """

    value = value.strip().removeprefix("base64-")

    try:
        session = json.loads(value)
    except json.JSONDecodeError:
        try:
            session = json.loads(base64.b64decode(value))
        except (ValueError, json.JSONDecodeError):
            Logger.print_error("Could not parse the session cookie (expected JSON or base64 JSON)")
            sys.exit(1)

    access_token = session.get("access_token")

    if not access_token:
        Logger.print_error("Session cookie does not contain an access_token")
        sys.exit(1)

    return access_token


def login_for_access_token(subdomain: str, anon_key: str, email: str, password: str) -> str:

    """
    Log in via Supabase Auth (password grant) and return the access token.
    """

    base_url = f"https://{subdomain}.supabase.co"

    try:
        response = requests.post(
            f"{base_url}/auth/v1/token",
            params = {"grant_type": "password"},
            headers = {"apikey": anon_key, "Content-Type": "application/json"},
            json = {"email": email, "password": password},
            timeout = 15,
        )
    except requests.RequestException as error:
        Logger.print_error(f"Login request failed: {error}")
        sys.exit(1)

    if response.status_code != 200:
        Logger.print_error(f"Login failed ({response.status_code}): {response.text[:120]}")
        sys.exit(1)

    access_token = response.json().get("access_token")

    if not access_token:
        Logger.print_error("Login response did not contain an access_token")
        sys.exit(1)

    return access_token


class InitializeProgram:

    def print_banner():

        """
        Print the banner to the console.
        """

        with open(CONFIG_DIR / "banner.txt", "r", encoding = "utf-8") as banner_file:
            banner = banner_file.read()

        Write.Print(banner + "\n", Colors.blue, interval = 0)
        return

    def parser_error(error_message: str):

        """
        Call when a parser error is encountered.
        """

        InitializeProgram.print_banner()
        Logger.print_error(f"There was an error: {error_message}")
        sys.exit(1)

    def parse_arguments():

        """
        Parse the command line arguments.
        """

        parser = argparse.ArgumentParser(
            epilog = "python supascan.py <subdomain> -a <anon_key> -b",
            description = "SupaBase weak RLS auditor"
        )
        parser.error = InitializeProgram.parser_error
        parser._optionals.title = "[ OPTIONS ]"
        parser.add_argument("subdomain", help = "The Supabase subdomain (example.supabase.co)")
        parser.add_argument("-a", "--anon_key", help = "The Supabase API key", required = True)
        parser.add_argument("-s", "--secret", help = "Is the Supabase API key a secret key", action = "store_true")
        parser.add_argument("-t", "--tables", nargs = "+", help = "Specific tables to audit (default: auto-discover)")
        parser.add_argument("--access_token", help = "An authenticated session JWT to use as the Bearer token")
        parser.add_argument("--cookie", help = "A Supabase auth cookie value (sb-<ref>-auth-token) to extract the session JWT from")
        parser.add_argument("--email", help = "Email for a password-grant login (used with --password)")
        parser.add_argument("--password", help = "Password for the password-grant login (used with --email)")
        parser.add_argument("-o", "--output", help = "The output directory to store the results in")
        parser.add_argument("-b", "--backup", help = "Extract all accessible tables from the Supabase database", action = "store_true")
        return parser.parse_args()

    def audit(self, tables: Optional[list[str]] = None) -> list[dict]:

        """
        Run a full audit on discovered tables.
        """

        Logger.print_info(f"Auditing {self.base_url}")
        key_label = "Secret key" if self.secret else "Anon key"
        Logger.print_info(f"Using {key_label}: {self.anon_key[:10]}...{self.anon_key[-4:]}")
        if self.secret:
            Logger.print_info("Secret key detected: RLS is bypassed and all tables are accessible")

        if not self.discovery.check_connection():
            Logger.print_warning("Cannot connect. Check subdomain and Anon key")
            sys.exit(1)

        Logger.print_info("Successfully connected")

        if not tables:
            Logger.print_info("Discovering tables...")
            tables = self.discovery.discover_tables_via_openapi()
            if not tables:
                Logger.print_warning("OpenAPI discovery failed. Trying the information schema")
                tables = self.discovery.discover_tables_via_schema()
            if not tables:
                Logger.print_warning("Schema discovery failed, probing candidates")
                tables = self.discovery.discover_tables_via_hints()
            if not tables:
                Logger.print_warning("Hint discovery failed, trying common names")
                tables = self.discovery.discover_tables_via_enumeration()
            if not tables:
                Logger.print_warning("No accessible tables found, quitting.")
                sys.exit(1)
            Logger.print_info(f"Found {len(tables):,} tables")

        results = []

        for table in tables:
            Logger.print_info(f"Checking {table}")
            result = self.discovery.check_rls_status(table)
            policies = self.discovery.check_rls_policies(table)
            result["policies"] = policies
            results.append(result)
            status = result["risk_level"]
            Logger.print_warning(f"Risk Level: {status}")
            for detail in result["details"]:
                Logger.print_info(f"    - {detail}")

        return results

    def print_report(self, results: list[dict]):

        """
        Print a formatted audit report.
        """

        for result in results:
            if result["risk_level"] in ("CRITICAL", "HIGH", "MEDIUM"):
                Logger.print_warning(f"{result['table']} - {result['risk_level']}")

    def __init__(self, subdomain, anon_key, secret, output, backup, tables, access_token):

        """
        The entry point for SupaScan.
        """

        self.subdomain = subdomain
        self.anon_key = anon_key
        self.secret = secret

        self.base_url = f"https://{self.subdomain}.supabase.co"

        self.discovery = SupabaseDiscovery(subdomain, anon_key, secret, access_token)
        self.extraction = SupabaseExtraction(subdomain, anon_key, secret, access_token)

        InitializeProgram.print_banner()
        print(Colors.white + f">> Subdomain : {subdomain}")
        print(Colors.white + f">> Anon Key  : {anon_key[:10]}")
        print(Colors.white + f">> Secret    : {secret}")
        print(Colors.white + f">> Session   : {'yes' if access_token else 'no'}")
        print(Colors.white + f">> Output    : {output}")
        print(Colors.white + f">> Backup    : {backup}")
        os_name = "Windows" if os.name == "nt" else "Unix"
        print(Colors.white + f">> OS        : {os_name}")
        Write.Print("------------ Scanning For Weak RLS ------------\n", Colors.blue, interval = 0)

        if secret:
            Logger.print_info("Secret key detected: RLS is bypassed and all tables are accessible")

        if backup:
            if not output:
                Logger.print_error("--output is required when using --backup")
                sys.exit(1)
            if not self.discovery.check_connection():
                Logger.print_warning("Cannot connect. Check subdomain and Anon key")
                sys.exit(1)
            Logger.print_info("Successfully connected")
            backup_data = self.extraction.backup_database(tables)
            self.extraction.export_backup_csv(backup_data, output)
            sys.exit(0)

        results = self.audit(tables)
        self.print_report(results)

        if output:
            self.extraction.export_json(results, output)

        return


if __name__ == "__main__":

    os.system("cls" if os.name == "nt" else "clear")
    os.system("title SupaBase" if os.name == "nt" else "printf '\\033]0;SupaBase\\007'")

    arguments = InitializeProgram.parse_arguments()

    subdomain = arguments.subdomain
    anon_key  = arguments.anon_key
    secret    = arguments.secret
    output    = arguments.output
    backup    = arguments.backup
    tables    = arguments.tables

    access_token = None

    if arguments.access_token:
        access_token = arguments.access_token
    elif arguments.cookie:
        access_token = decode_session_cookie(arguments.cookie)

    if arguments.email or arguments.password:
        if access_token:
            Logger.print_warning("An access token was provided; ignoring --email/--password")
        else:
            email = arguments.email or Logger.custom_input("Email: ")
            password = arguments.password or getpass.getpass("Password: ")
            access_token = login_for_access_token(subdomain, anon_key, email, password)

    if access_token:
        Logger.print_info("Using an authenticated session for this scan")

    InitializeProgram(subdomain, anon_key, secret, output, backup, tables, access_token)
