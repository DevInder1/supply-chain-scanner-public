from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class VulnerabilityDatabase:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.db_path)
        self.connection.row_factory = sqlite3.Row
        self._initialize()

    def close(self) -> None:
        self.connection.close()

    def _initialize(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS advisories (
                advisory_id TEXT PRIMARY KEY,
                payload TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS package_advisories (
                package_name TEXT NOT NULL,
                ecosystem TEXT NOT NULL,
                advisory_id TEXT NOT NULL,
                UNIQUE(package_name, ecosystem, advisory_id)
            );

            CREATE TABLE IF NOT EXISTS epss_scores (
                cve TEXT PRIMARY KEY,
                score REAL,
                percentile REAL,
                payload TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS kev_entries (
                cve TEXT PRIMARY KEY,
                payload TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS nvd_cves (
                cve_id TEXT NOT NULL,
                package_name TEXT NOT NULL,
                payload TEXT NOT NULL,
                UNIQUE(cve_id, package_name)
            );

            CREATE TABLE IF NOT EXISTS ghsa_advisories (
                ghsa_id TEXT NOT NULL,
                package_name TEXT NOT NULL,
                ecosystem TEXT NOT NULL,
                payload TEXT NOT NULL,
                UNIQUE(ghsa_id, package_name, ecosystem)
            );

            CREATE TABLE IF NOT EXISTS ossindex_vulns (
                vuln_id TEXT NOT NULL,
                coordinate TEXT NOT NULL,
                payload TEXT NOT NULL,
                UNIQUE(vuln_id, coordinate)
            );
            """
        )
        self.connection.commit()

    def store_package_advisories(self, package_name: str, ecosystem: str, advisories: list[dict[str, Any]]) -> None:
        advisory_rows = []
        link_rows = []
        for advisory in advisories:
            advisory_id = advisory.get("id")
            if not advisory_id:
                continue
            advisory_rows.append((advisory_id, json.dumps(advisory)))
            link_rows.append((package_name.lower(), ecosystem, advisory_id))

        with self.connection:
            self.connection.executemany(
                "INSERT OR REPLACE INTO advisories (advisory_id, payload) VALUES (?, ?)",
                advisory_rows,
            )
            self.connection.executemany(
                "INSERT OR IGNORE INTO package_advisories (package_name, ecosystem, advisory_id) VALUES (?, ?, ?)",
                link_rows,
            )

    def advisory_lookup(self) -> dict[tuple[str, str], list[dict[str, Any]]]:
        cursor = self.connection.execute(
            """
            SELECT package_name, ecosystem, payload
            FROM package_advisories
            JOIN advisories USING(advisory_id)
            """
        )
        lookup: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for row in cursor.fetchall():
            key = (str(row["package_name"]), str(row["ecosystem"]))
            lookup.setdefault(key, []).append(json.loads(row["payload"]))
        return lookup

    def store_epss_score(
        self,
        *,
        cve: str,
        score: float | None,
        percentile: float | None,
        raw_payload: dict[str, Any],
    ) -> None:
        with self.connection:
            self.connection.execute(
                "INSERT OR REPLACE INTO epss_scores (cve, score, percentile, payload) VALUES (?, ?, ?, ?)",
                (cve, score, percentile, json.dumps(raw_payload)),
            )

    def has_epss_score(self, cve: str) -> bool:
        cursor = self.connection.execute("SELECT 1 FROM epss_scores WHERE cve = ?", (cve,))
        return cursor.fetchone() is not None

    def epss_lookup(self) -> dict[str, dict[str, Any]]:
        cursor = self.connection.execute("SELECT cve, score, percentile, payload FROM epss_scores")
        return {
            str(row["cve"]): {
                "score": row["score"],
                "percentile": row["percentile"],
                "payload": json.loads(row["payload"]),
            }
            for row in cursor.fetchall()
        }

    def store_kev_entry(self, cve: str, payload: dict[str, Any]) -> None:
        with self.connection:
            self.connection.execute(
                "INSERT OR REPLACE INTO kev_entries (cve, payload) VALUES (?, ?)",
                (cve, json.dumps(payload)),
            )

    def kev_lookup(self) -> dict[str, dict[str, Any]]:
        cursor = self.connection.execute("SELECT cve, payload FROM kev_entries")
        return {str(row["cve"]): json.loads(row["payload"]) for row in cursor.fetchall()}

    def kev_catalog_loaded(self) -> bool:
        cursor = self.connection.execute("SELECT value FROM metadata WHERE key = 'kev_catalog_loaded'")
        row = cursor.fetchone()
        return bool(row and row["value"] == "true")

    def mark_kev_catalog_loaded(self) -> None:
        with self.connection:
            self.connection.execute(
                "INSERT OR REPLACE INTO metadata (key, value) VALUES ('kev_catalog_loaded', 'true')"
            )

    def get_metadata(self, key: str) -> str | None:
        cursor = self.connection.execute("SELECT value FROM metadata WHERE key = ?", (key,))
        row = cursor.fetchone()
        if not row:
            return None
        return str(row["value"])

    def set_metadata(self, key: str, value: str) -> None:
        with self.connection:
            self.connection.execute(
                "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
                (key, value),
            )

    def get_last_sync_time(self, source_name: str) -> datetime | None:
        value = self.get_metadata(f"sync_last_{source_name}")
        if not value:
            return None
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None

    def set_last_sync_time(self, source_name: str, when: datetime | None = None) -> None:
        timestamp = when or datetime.now(timezone.utc)
        self.set_metadata(f"sync_last_{source_name}", timestamp.isoformat())

    # ----- NVD -----

    def store_nvd_cves(self, package_name: str, cves: list[dict[str, Any]]) -> None:
        rows = []
        for cve in cves:
            cve_id = cve.get("id") or cve.get("cve_id")
            if not cve_id:
                continue
            rows.append((cve_id, package_name.lower(), json.dumps(cve)))
        if rows:
            with self.connection:
                self.connection.executemany(
                    "INSERT OR REPLACE INTO nvd_cves (cve_id, package_name, payload) VALUES (?, ?, ?)",
                    rows,
                )

    def nvd_lookup(self) -> dict[str, list[dict[str, Any]]]:
        cursor = self.connection.execute("SELECT package_name, payload FROM nvd_cves")
        lookup: dict[str, list[dict[str, Any]]] = {}
        for row in cursor.fetchall():
            lookup.setdefault(str(row["package_name"]), []).append(json.loads(row["payload"]))
        return lookup

    # ----- GHSA -----

    def store_ghsa_advisories(self, package_name: str, ecosystem: str, advisories: list[dict[str, Any]]) -> None:
        rows = []
        for adv in advisories:
            ghsa_id = adv.get("ghsa_id") or adv.get("id")
            if not ghsa_id:
                continue
            rows.append((ghsa_id, package_name.lower(), ecosystem, json.dumps(adv)))
        if rows:
            with self.connection:
                self.connection.executemany(
                    "INSERT OR REPLACE INTO ghsa_advisories (ghsa_id, package_name, ecosystem, payload) VALUES (?, ?, ?, ?)",
                    rows,
                )

    def ghsa_lookup(self) -> dict[tuple[str, str], list[dict[str, Any]]]:
        cursor = self.connection.execute("SELECT package_name, ecosystem, payload FROM ghsa_advisories")
        lookup: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for row in cursor.fetchall():
            key = (str(row["package_name"]), str(row["ecosystem"]))
            lookup.setdefault(key, []).append(json.loads(row["payload"]))
        return lookup

    # ----- OSS Index -----

    def store_ossindex_vulns(self, coordinate: str, vulns: list[dict[str, Any]]) -> None:
        rows = []
        for vuln in vulns:
            vuln_id = vuln.get("id") or vuln.get("reference")
            if not vuln_id:
                continue
            rows.append((vuln_id, coordinate, json.dumps(vuln)))
        if rows:
            with self.connection:
                self.connection.executemany(
                    "INSERT OR REPLACE INTO ossindex_vulns (vuln_id, coordinate, payload) VALUES (?, ?, ?)",
                    rows,
                )

    def ossindex_lookup(self) -> dict[str, list[dict[str, Any]]]:
        cursor = self.connection.execute("SELECT coordinate, payload FROM ossindex_vulns")
        lookup: dict[str, list[dict[str, Any]]] = {}
        for row in cursor.fetchall():
            lookup.setdefault(str(row["coordinate"]), []).append(json.loads(row["payload"]))
        return lookup