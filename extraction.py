import requests
import datetime
import csv
import os
import json

from typing import Optional

from discover import SupabaseDiscovery
from utility.logger import Logger

class SupabaseExtraction:

    def __init__(self, subdomain: str, anon_key: str, secret: bool = False, access_token: Optional[str] = None):

        self.subdomain = subdomain
        self.anon_key = anon_key
        self.secret = secret
        self.access_token = access_token

        self.base_url = f"https://{self.subdomain}.supabase.co"
        self.rest_url = f"{self.base_url}/rest/v1"
        self.headers = {

            "apikey": anon_key,
            "Authorization": f"Bearer {access_token or anon_key}",
            "Content-Type": "application/json"

        }

    def dump_table(self, table_name: str) -> list[dict]:

        """
        Extract all rows from a table using pagination.
        """

        rows: list[dict] = []
        offset = 0
        page_size = 1000

        while True:
            parameters = {

                "select": "*",
                "offset": str(offset),
                "limit": str(page_size),

            }

            try:
                response = requests.get(f"{self.rest_url}/{table_name}", headers = self.headers, params = parameters, timeout = 30)
                status_code = response.status_code
            except requests.RequestException as error:
                Logger.print_error(f"Error dumping {table_name}: {error}")
                break

            if status_code == 200:
                page = response.json()
                rows.extend(page)
            elif response.status_code == 401:
                if not rows:
                    Logger.print_warning(f"{table_name} key not permitted to read")
                break
            elif status_code == 404:
                if not rows:
                    print(f"{table_name} not found")
                break
            else:
                print(f"{table_name} unexpected status: {status_code}")
                break

            if len(page) < page_size:
                break

            offset += page_size

        return rows

    def backup_database(self, tables: Optional[list[str]] = None) -> dict:

        """
        Full database extract from all accessible tables.
        """

        discovery_module = SupabaseDiscovery(self.subdomain, self.anon_key, self.secret, self.access_token)

        Logger.print_info("Starting database extraction...")

        if not tables:
            Logger.print_info("Discovering tables...")
            tables = discovery_module.discover_tables_via_openapi()
            if not tables:
                Logger.print_warning("OpenAPI discovery failed. Trying the information schema")
                tables = discovery_module.discover_tables_via_schema()
            if not tables:
                Logger.print_warning("Schema discovery failed, probing candidates")
                tables = discovery_module.discover_tables_via_hints()
            if not tables:
                Logger.print_warning("Hint discovery failed, trying common names")
                tables = discovery_module.discover_tables_via_enumeration()

        Logger.print_info(f"Extracting {len(tables):,} tables")

        backup: dict = {

            "meta": {
                "target": self.base_url,
                "subdomain": self.subdomain,
                "anon_key": f"...{self.anon_key[-4:]}" if self.anon_key else None,
                "extracted_at": None,
                "tables": tables
            },
            "tables": {}

        }

        backup["meta"]["extracted_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()

        total_rows = 0

        for table in tables:
            Logger.print_info(f"Dumping records for {table}")
            rows = self.dump_table(table)
            backup["tables"][table] = rows
            total_rows += len(rows)
            Logger.print_info(f"{len(rows):,} records dumped from {table}")

        backup["meta"]["total_rows"] = total_rows

        Logger.print_success(f"Extraction complete: {total_rows:,} across {len(tables):,} tables")

        return backup

    def export_backup_csv(self, backup: dict, output_directory: str):

        """
        Write a backup to one CSV file per table.
        """

        os.makedirs(output_directory, exist_ok = True)
        tables = backup.get("tables", {})

        for table, rows in tables.items():
            if not rows:
                Logger.print_warning(f"No rows extracted from {table}, no CSV file produced")
                continue
            fieldnames = []
            for row in rows:
                for key in row:
                    if key not in fieldnames:
                        fieldnames.append(key)

            path = os.path.join(output_directory, f"{table}.csv")
            with open(path, "w", newline = "") as file:
                writer = csv.DictWriter(file, fieldnames = fieldnames)
                writer.writeheader()
                for row in rows:
                    writer.writerow({
                        k: json.dumps(v, ensure_ascii = False) if isinstance(v, (dict, list)) else v for k, v in row.items()
                    })
            Logger.print_info(f"{table}: {len(rows):,} -> {path}")
        Logger.print_success(f"CSV extraction written to {output_directory}/*, ({len(tables)} tables)")

    def export_json(self, results: list[dict], output_directory: str):

        """
        Export results to a JSON file inside the output directory.
        """

        os.makedirs(output_directory, exist_ok = True)
        path = os.path.join(output_directory, "audit_results.json")
        data = {

            "target": self.base_url,
            "results": results

        }

        with open(path, "w") as file:
            json.dump(data, file, indent = 4, default = str)

        Logger.print_info(f"JSON results exported to {path}")