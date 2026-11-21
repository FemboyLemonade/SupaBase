import concurrent.futures
import json
import requests

from typing import Optional

from utility.logger import Logger
from utility.load_tables import load_tables_config

class SupabaseDiscovery:

    def __init__(self, subdomain: str, anon_key: str, secret: bool = False, access_token: Optional[str] = None):

        self.subdomain = subdomain
        self.anon_key = anon_key
        self.secret = secret
        self.access_token = access_token
        self.candidates = load_tables_config()["candidates"]

        self.base_url = f"https://{self.subdomain}.supabase.co"
        self.rest_url = f"{self.base_url}/rest/v1"
        self.headers = {

            "apikey": anon_key,
            "Authorization": f"Bearer {access_token or anon_key}",
            "Content-Type": "application/json"

        }
        self.session = requests.Session()

    def pick_existing_filter(self, result: dict):

        """
        Return a (column, filter_value) pair so UPDATE/DELETE tests can work.
        """

        sample = result.get("sample_data")
        if not sample:
            return None, None
        row = sample[0]

        if row.get("id") is not None:
            return "id", f"eq.{row['id']}"

        for column in ("created_at", "email", "uuid", "unique_id", "phone", "username"):
            if column in row and row[column] is not None:
                return column, f"eq.{row[column]}"

        column = list(row.keys())[0]

        return column, f"eq.{row[column]}"

    def nomatch_value(self, result: dict) -> str:

        """
        Return a filter value guaranteed to match no rows.
        """

        sample = result.get("sample_data")
        if not sample:
            return "eq.__rls_audit_nomatch__"
        row = sample[0]
        for column in ("id", "created_at", "email", "uuid", "unique_id", "phone", "username"):
            if column in row:
                value = row[column]
                if isinstance(value, bool):
                    return "eq.false" if value else "eq.true__never__"
                if isinstance(value, int):
                    return "eq.-999999999"
                if isinstance(value, str) and len(value) > 10:
                    return "eq.00000000-0000-0000-0000-000000000000"
        column = list(row.keys())[0]
        value = row[column]
        if isinstance(value, bool):
            return "eq.false"
        if isinstance(value, int):
            return "eq.-999999999"
        return "eq.__rls_audit_nomatch__"

    def check_connection(self) -> bool:

        """
        Verify that the anon key works and can connect to the instance.
        """

        probes = ["/auth/v1/health", "/rest/v1/", "/rest/v1/*"]

        for probe in probes:
            try:
                response = self.session.get(f"{self.base_url}{probe}", headers = self.headers, timeout = 15)
                if response.status_code in (200, 401, 403, 404):
                    return True
            except requests.RequestException:
                continue

        return False

    def _probe_names(self, names: list[str], workers: int = 16) -> list[str]:

        """
        Probe candidate table names concurrently. A 200 means the table is
        exposed; a 404 with a PostgREST 'Perhaps you meant' hint reveals a
        similarly named table.
        """

        found: set[str] = set()
        parameters = {

            "select": "*",
            "limit": "0"

        }

        def probe(name: str):

            try:
                response = self.session.get(f"{self.rest_url}/{name}", headers = self.headers, params = parameters, timeout = 5)
                status_code = response.status_code
            except requests.RequestException:
                return

            if status_code == 200:
                found.add(name)
                return

            if status_code != 404:
                return

            try:
                payload = response.json()
            except json.JSONDecodeError:
                return

            message = payload.get("message", "")
            hint = payload.get("hint") or ""

            for text in (hint, message):
                if "Perhaps you meant" not in text:
                    continue
                start = text.find("'")
                if start == -1:
                    continue
                end = text.find("'", start + 1)
                if end != -1:
                    table = text[start + 1 : end]
                else:
                    table = text[start + 1 :].strip(".'")
                table = table.split(".")[-1]
                if table:
                    found.add(table)

        with concurrent.futures.ThreadPoolExecutor(max_workers = workers) as executor:
            for _ in executor.map(probe, names):
                pass

        return sorted(found)

    def discover_tables_via_hints(self) -> list[str]:

        """
        Discover tables from PostgREST 'Perhaps you meant' hints,
        probing candidate names concurrently.
        """

        return self._probe_names(self.candidates)

    def discover_tables_via_openapi(self) -> list[str]:

        """
        Discover all tables via the PostgREST OpenAPI spec at the /rest/v1 root.
        """

        tables: set[str] = set()

        try:
            response = self.session.get(f"{self.rest_url}/", headers = self.headers, timeout = 15)
            if response.status_code == 200:
                spec = response.json()
                for path in spec.get("paths", {}):
                    name = path.strip("/")
                    if not name or name.startswith("rpc/"):
                        continue
                    tables.add(name)
        except (requests.RequestException, json.JSONDecodeError, ValueError):
            pass

        return sorted(tables)

    def discover_tables_via_schema(self) -> list[str]:

        """
        Discover tables from the information schema.
        """

        tables = []
        endpoints = [
            f"{self.rest_url}/information_schema.tables",
            f"{self.rest_url}/?table=information_schema.tables"
        ]
        parameters = {

            "select": "*",
            "limit": "1000"

        }

        for endpoint in endpoints:
            try:
                response = self.session.get(endpoint, headers = self.headers, params = parameters, timeout = 15)
                if response.status_code == 200:
                    data = response.json()
                    for row in data:
                        table_name = row.get("table_name")
                        schema = row.get("table_schema", "public")
                        if table_name and schema == "public":
                            tables.append(table_name)
                    if tables:
                        return list(set(tables))
            except (requests.RequestException, json.JSONDecodeError):
                pass

        return sorted(tables)

    def discover_tables_via_enumeration(self, common_names: Optional[list[str]] = None) -> list[str]:

        """
        Try common table names to discover accessible tables.
        """

        if common_names is None:
            common_names = self.candidates

        return self._probe_names(common_names)

    def check_rls_status(self, table_name: str) -> dict:

        """
        Check the RLS status for a specific table.
        """

        result = {

            "table": table_name,
            "rls_enabled": None,
            "select_allowed": False,
            "insert_allowed": False,
            "update_allowed": False,
            "delete_allowed": False,
            "row_count": 0,
            "sample_data": None,
            "risk_level": "unknown",
            "details": []

        }
        parameters = {

            "select": "*",
            "limit": "5"

        }

        # Test SELECT

        try:
            response = self.session.get(f"{self.rest_url}/{table_name}", headers = self.headers, params = parameters, timeout = 15)
            if response.status_code == 200:
                data = response.json()
                result["select_allowed"] = True
                result["row_count"] = len(data)
                result["sample_data"] = data[:2] if data else None
                result["details"].append(f"SELECT allowed - returned {len(data):,} rows")
            elif response.status_code == 403:
                result["details"].append("SELECT denied (RLS active)")
            elif response.status_code == 404:
                result["details"].append("Table not found or not exposed")
                return result
        except requests.RequestException as error:
            result["details"].append(f"SELECT error: {error}")

        # Test INSERT

        try:
            response = self.session.post(f"{self.rest_url}/{table_name}", headers = self.headers, json = {}, timeout = 15)
            status_code = response.status_code
            if status_code in (200, 201):
                result["insert_allowed"] = True
                result["details"].append("INSERT allowed without auth")
            elif status_code in (401, 403):
                body = ""
                try:
                    body = response.json().get("message", "")
                except json.JSONDecodeError:
                    pass
                result["details"].append(f"INSERT denied (RLS is active) - {body[:80]}")
        except requests.RequestException:
            pass

        # Test UPDATE

        update_column, update_value = self.pick_existing_filter(result)

        if update_column:
            try:
                headers = dict(self.headers)
                headers["Prefer"] = "count=exact"
                parameters = {update_column: update_value}
                response = self.session.patch(f"{self.rest_url}/{table_name}", headers = headers, params = parameters, timeout = 15)
                status_code = response.status_code
                content_range = response.headers.get("Content-Range", "")
                if status_code in (200, 204):
                    if "1" in content_range:
                        result["update_allowed"] = True
                        result["details"].append("UPDATE is permitted by RLS using a (tested with a no-op write)")
                    else:
                        result["details"].append("UPDATE blocked by RLS")
                elif status_code in (401, 403):
                    result["details"].append("UPDATE forbidden by RLS")
                else:
                    result["details"].append(f"UPDATE test inconclusive: {status_code}")
            except requests.RequestException as error:
                result["details"].append(f"UPDATE error: {error}")

        # Test DELETE

        if update_column:
            try:
                headers = dict(self.headers)
                headers["Prefer"] = "count=exact"
                parameters = {update_column: self.nomatch_value(result)}
                response = self.session.delete(f"{self.rest_url}/{table_name}", headers = headers, params = parameters, timeout = 15)
                status_code = response.status_code
                if status_code in (401, 403):
                    result["details"].append("DELETE is forbidden by RLS")
                elif status_code == 204:
                    result["details"].append("DELETE is inconclusive (silent)")
                else:
                    result["details"].append(f"DELETE test inconclusive: {status_code}")
            except requests.RequestException as error:
                result["details"].append(f"DELETE error: {error}")

        # Determine Risk Level

        if result["select_allowed"] and result["insert_allowed"]:
            result["risk_level"] = "CRITICAL"
            result["rls_enabled"] = False
        elif result["select_allowed"] or result["insert_allowed"]:
            result["risk_level"] = "HIGH"
            result["rls_enabled"] = False
        elif any(op in str(result["details"]) for op in ["denied", "RLS active"]):
            result["risk_level"] = "LOW"
            result["rls_enabled"] = True
        else:
            result["risk_level"] = "INFO"
            result["rls_enabled"] = None

        if (result["update_allowed"] or result["delete_allowed"]) and result["risk_level"] in ("LOW", "INFO", "unknown"):
            result["risk_level"] = "HIGH"

        return result

    def check_rls_policies(self, table_name: str) -> list[dict]:

        """
        Try to discover RLS policies for a table.
        """

        policies = []

        parameters={

            "select": "policyname,permissive,roles,cmd,qual,with_check",
            "tablename": f"eq.{table_name}"

        }

        try:
            response = self.session.get(f"{self.rest_url}/pg_policies", headers = self.headers, params = parameters, timeout = 15)
            if response.status_code == 200:
                policies = response.json()
        except requests.RequestException:
            pass

        return policies