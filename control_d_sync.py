#!/usr/bin/env python3
"""
 ██████╗████████╗██████╗ ██╗     ██████╗
██╔════╝╚══██╔══╝██╔══██╗██║     ██╔══██╗
██║        ██║   ██████╔╝██║     ██║  ██║
██║        ██║   ██╔══██╗██║     ██║  ██║
╚██████╗   ██║   ██║  ██║███████╗██████╔╝
 ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═════╝


███████╗██╗   ██╗███╗   ██╗ ██████╗
██╔════╝╚██╗ ██╔╝████╗  ██║██╔════╝
███████╗ ╚████╔╝ ██╔██╗ ██║██║
╚════██║  ╚██╔╝  ██║╚██╗██║██║
███████║   ██║   ██║ ╚████║╚██████╗
╚══════╝   ╚═╝   ╚═╝  ╚═══╝ ╚═════╝

--------------
Keeps Control D profile folders in sync with remote block-lists.

Workflow per profile
  1. Fetch all remote JSON block-lists (concurrently).
  2. Delete any existing managed folders by name.
  3. Re-create every folder and push its rules in batches.

Usage
  python control_d_sync.py [--dry-run] [--log-level DEBUG|INFO|WARNING]
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
# import time
from dataclasses import dataclass, field
from typing import Any

import httpx
from dotenv import load_dotenv

# --------------------------------------------------------------------------- #
# Bootstrap
# --------------------------------------------------------------------------- #
load_dotenv()
logging.getLogger("httpx").setLevel(logging.WARNING)


def _build_logger(level: str = "INFO") -> logging.Logger:
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s", "%H:%M:%S")
    )
    logger = logging.getLogger("cdsync")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.addHandler(handler)
    return logger


log = _build_logger(os.getenv("LOG_LEVEL", "INFO"))


# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Config:
    token: str
    profile_ids: list[str]
    folder_urls: list[str]
    batch_size: int = 500
    max_retries: int = 3
    retry_base_delay: float = 1.0
    folder_creation_delay: float = 2.0

    @classmethod
    def from_env(cls) -> "Config":
        token = os.getenv("TOKEN", "").strip()
        profiles_raw = os.getenv("PROFILE", "").strip()
        if not token or not profiles_raw:
            raise ValueError("TOKEN and PROFILE must be set in the environment.")

        return cls(
            token=token,
            profile_ids=[p.strip() for p in profiles_raw.split(",") if p.strip()],
            folder_urls=[
                "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/badware-hoster-folder.json",
                "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/native-tracker-amazon-folder.json",
                "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/native-tracker-microsoft-folder.json",
                "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/native-tracker-tiktok-aggressive-folder.json",
                "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/referral-allow-folder.json",
                "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/spam-idns-folder.json",
                "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/ultimate-known_issues-allow-folder.json",
                "https://raw.githubusercontent.com/yokoffing/Control-D-Config/refs/heads/main/folders/potentially-malicious-ips.json",
            ],
        )


# --------------------------------------------------------------------------- #
# Result types
# --------------------------------------------------------------------------- #
@dataclass
class FolderResult:
    name: str
    created: bool = False
    rules_attempted: int = 0
    rules_pushed: int = 0
    rules_skipped: int = 0
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.created and self.error is None


@dataclass
class ProfileResult:
    profile_id: str
    folders: list[FolderResult] = field(default_factory=list)
    fetch_errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return (
            not self.fetch_errors
            and bool(self.folders)
            and all(f.ok for f in self.folders)
        )

    def summary(self) -> str:
        ok = sum(1 for f in self.folders if f.ok)
        total = len(self.folders)
        total_rules = sum(f.rules_pushed for f in self.folders)
        skipped = sum(f.rules_skipped for f in self.folders)
        return (
            f"Profile {self.profile_id}: {ok}/{total} folders OK | "
            f"{total_rules} rules pushed | {skipped} duplicates skipped"
        )


# --------------------------------------------------------------------------- #
# HTTP layer
# --------------------------------------------------------------------------- #
class ApiClient:
    BASE = "https://api.controld.com/profiles"

    def __init__(self, cfg: Config) -> None:
        self._cfg = cfg
        self._client = httpx.AsyncClient(
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {cfg.token}",
            },
            timeout=30,
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        last_exc: Exception | None = None
        for attempt in range(self._cfg.max_retries):
            try:
                resp = await self._client.request(method, url, **kwargs)
                resp.raise_for_status()
                return resp
            except (httpx.HTTPError, httpx.TimeoutException) as exc:
                last_exc = exc
                if attempt < self._cfg.max_retries - 1:
                    delay = self._cfg.retry_base_delay * (2**attempt)
                    log.warning(
                        "Attempt %d/%d failed for %s %s – retrying in %.1fs: %s",
                        attempt + 1,
                        self._cfg.max_retries,
                        method,
                        url,
                        delay,
                        exc,
                    )
                    await asyncio.sleep(delay)
        assert last_exc is not None
        raise last_exc

    async def get(self, path: str) -> dict:
        r = await self._request("GET", f"{self.BASE}{path}")
        return r.json()

    async def delete(self, path: str) -> None:
        await self._request("DELETE", f"{self.BASE}{path}")

    async def post_form(self, path: str, data: dict) -> dict:
        r = await self._request(
            "POST",
            f"{self.BASE}{path}",
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        return r.json()


class GithubClient:
    """Fetches remote JSON block-list files (with a shared connection pool)."""

    def __init__(self) -> None:
        self._client = httpx.AsyncClient(timeout=30)
        self._cache: dict[str, dict] = {}

    async def close(self) -> None:
        await self._client.aclose()

    async def fetch(self, url: str) -> dict:
        if url not in self._cache:
            r = await self._client.get(url)
            r.raise_for_status()
            self._cache[url] = r.json()
        return self._cache[url]

    async def fetch_all(self, urls: list[str]) -> list[tuple[str, dict | Exception]]:
        """Fetch all URLs concurrently. Returns (url, result_or_exception) pairs."""
        tasks = [self.fetch(url) for url in urls]
        results: list[dict | Exception] = await asyncio.gather(*tasks, return_exceptions=True)
        return list(zip(urls, results))


# --------------------------------------------------------------------------- #
# Sync logic
# --------------------------------------------------------------------------- #
class ProfileSyncer:
    def __init__(self, api: ApiClient, cfg: Config, dry_run: bool = False) -> None:
        self._api = api
        self._cfg = cfg
        self._dry_run = dry_run

    # -- Folder helpers -------------------------------------------------------

    async def _list_folders(self, profile_id: str) -> dict[str, str]:
        """Return {folder_name: folder_id}."""
        data = await self._api.get(f"/{profile_id}/groups")
        return {
            g["group"].strip(): str(g["PK"])
            for g in data.get("body", {}).get("groups", [])
            if g.get("group") and g.get("group").strip() and g.get("PK")
        }

    async def _existing_hostnames(self, profile_id: str) -> set[str]:
        """Collect every hostname already present in every folder + root."""
        hostnames: set[str] = set()

        async def _harvest(path: str, label: str) -> None:
            try:
                data = await self._api.get(path)
                rules = data.get("body", {}).get("rules", [])
                for r in rules:
                    if r.get("PK"):
                        hostnames.add(r["PK"])
                log.debug("Harvested %d rules from %s", len(rules), label)
            except httpx.HTTPError as exc:
                log.warning("Could not harvest rules from %s: %s", label, exc)

        # Root + all current folders in parallel
        folders = await self._list_folders(profile_id)
        tasks = [_harvest(f"/{profile_id}/rules", "root")] + [
            _harvest(f"/{profile_id}/rules/{fid}", f"folder:{name}")
            for name, fid in folders.items()
        ]
        await asyncio.gather(*tasks)
        log.info("Total existing hostnames across profile: %d", len(hostnames))
        return hostnames

    async def _delete_folder(self, profile_id: str, name: str, folder_id: str) -> None:
        if self._dry_run:
            log.info("[DRY-RUN] Would delete folder '%s' (ID %s)", name, folder_id)
            return
        await self._api.delete(f"/{profile_id}/groups/{folder_id}")
        log.info("Deleted folder '%s' (ID %s)", name, folder_id)

    async def _create_folder(
        self, profile_id: str, name: str, do: int, status: int
    ) -> str | None:
        if self._dry_run:
            log.info("[DRY-RUN] Would create folder '%s' (do=%d status=%d)", name, do, status)
            return "dry-run-id"

        await self._api.post_form(
            f"/{profile_id}/groups",
            data={"name": name, "do": str(do), "status": str(status)},
        )
        await asyncio.sleep(self._cfg.folder_creation_delay)

        folders = await self._list_folders(profile_id)
        folder_id = folders.get(name)
        if folder_id:
            log.info("Created folder '%s' (ID %s)", name, folder_id)
            return folder_id

        log.error("Folder '%s' not found after creation", name)
        return None

    # -- Rule helpers ---------------------------------------------------------

    async def _push_rules(
        self,
        profile_id: str,
        result: FolderResult,
        folder_id: str,
        do: int,
        status: int,
        hostnames: list[str],
        seen: set[str],
    ) -> None:
        new_hosts = [h for h in hostnames if h not in seen]
        skipped = len(hostnames) - len(new_hosts)

        result.rules_attempted = len(hostnames)
        result.rules_skipped = skipped

        if skipped:
            log.info("Folder '%s': skipping %d duplicates", result.name, skipped)

        if not new_hosts:
            log.info("Folder '%s': nothing new to push", result.name)
            return

        cfg = self._cfg
        total_batches = (len(new_hosts) + cfg.batch_size - 1) // cfg.batch_size

        for batch_num, start in enumerate(range(0, len(new_hosts), cfg.batch_size), 1):
            batch = new_hosts[start : start + cfg.batch_size]

            if self._dry_run:
                log.info(
                    "[DRY-RUN] Folder '%s' – would push batch %d/%d (%d rules)",
                    result.name, batch_num, total_batches, len(batch),
                )
                result.rules_pushed += len(batch)
                seen.update(batch)
                continue

            data: dict[str, str] = {
                "do": str(do),
                "status": str(status),
                "group": str(folder_id),
            }
            for j, host in enumerate(batch):
                data[f"hostnames[{j}]"] = host

            try:
                await self._api.post_form(f"/{profile_id}/rules", data=data)
                result.rules_pushed += len(batch)
                seen.update(batch)
                log.info(
                    "Folder '%s' – batch %d/%d: pushed %d rules",
                    result.name, batch_num, total_batches, len(batch),
                )
            except httpx.HTTPError as exc:
                msg = f"batch {batch_num} failed: {exc}"
                log.error("Folder '%s' – %s", result.name, msg)
                result.error = msg  # non-fatal: continue other batches

        log.info(
            "Folder '%s' – done (%d pushed, %d skipped)",
            result.name, result.rules_pushed, result.rules_skipped,
        )

    # -- Top-level sync -------------------------------------------------------

    async def sync(self, profile_id: str, folder_data_list: list[dict]) -> ProfileResult:
        pr = ProfileResult(profile_id=profile_id)

        # Validate folder data structure
        valid_folders = []
        for fd in folder_data_list:
            if not isinstance(fd, dict) or not isinstance(fd.get("group"), dict):
                log.warning("Skipping folder with invalid structure")
                continue
            valid_folders.append(fd)

        # 1. Delete managed folders that already exist
        existing = await self._list_folders(profile_id)
        delete_tasks = []
        for fd in valid_folders:
            grp_name = fd.get("group", {}).get("group", "").strip()
            if grp_name and grp_name in existing:
                delete_tasks.append(self._delete_folder(profile_id, grp_name, existing[grp_name]))
        if delete_tasks:
            await asyncio.gather(*delete_tasks)

        # 2. Snapshot hostnames still present (other folders, root, etc.)
        seen = await self._existing_hostnames(profile_id)

        # 3. Create folders sequentially (API is finicky with concurrent creates)
        for fd in valid_folders:
            grp = fd.get("group", {})
            name = grp.get("group", "").strip()
            if not name:
                log.warning("Skipping folder with missing or empty 'group' name")
                continue
            do: int = grp.get("action", {}).get("do", 1)
            status: int = grp.get("action", {}).get("status", 1)
            hostnames: list[str] = [r["PK"] for r in fd.get("rules", []) if r.get("PK")]

            fr = FolderResult(name=name)
            pr.folders.append(fr)

            folder_id = await self._create_folder(profile_id, name, do, status)
            if folder_id is None:
                fr.error = "folder creation failed"
                continue

            fr.created = True
            await self._push_rules(profile_id, fr, folder_id, do, status, hostnames, seen)

        return pr


# --------------------------------------------------------------------------- #
# Entry-point
# --------------------------------------------------------------------------- #
async def _run(cfg: Config, dry_run: bool) -> int:
    gh = GithubClient()
    api = ApiClient(cfg)

    try:
        # Fetch all block-lists once (shared across all profiles)
        log.info("Fetching %d block-list(s) from GitHub…", len(cfg.folder_urls))
        raw_results = await gh.fetch_all(cfg.folder_urls)

        folder_data_list: list[dict] = []
        for url, result in raw_results:
            if isinstance(result, Exception):
                log.error("Failed to fetch %s: %s", url, result)
            else:
                folder_data_list.append(result)

        if not folder_data_list:
            log.error("No block-lists could be fetched – aborting.")
            return 1

        log.info("Fetched %d/%d block-list(s) successfully.", len(folder_data_list), len(cfg.folder_urls))

        # Sync each profile (sequentially to avoid hammering the API)
        syncer = ProfileSyncer(api, cfg, dry_run=dry_run)
        profile_results: list[ProfileResult] = []

        for pid in cfg.profile_ids:
            log.info("── Starting sync for profile %s ──", pid)
            pr = await syncer.sync(pid, folder_data_list)
            profile_results.append(pr)
            log.info(pr.summary())

        # Final summary
        ok = sum(1 for pr in profile_results if pr.ok)
        log.info("═══ All done: %d/%d profile(s) fully successful ═══", ok, len(profile_results))
        return 0 if ok == len(profile_results) else 1

    finally:
        await gh.close()
        await api.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Sync Control-D folders from remote block-lists.")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview changes without touching the API.",
    )
    parser.add_argument(
        "--log-level",
        default=os.getenv("LOG_LEVEL", "INFO"),
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    args = parser.parse_args()

    # Re-apply log level now that we have the CLI arg
    log.setLevel(getattr(logging, args.log_level))

    try:
        cfg = Config.from_env()
    except ValueError as exc:
        log.error("%s", exc)
        sys.exit(1)

    if args.dry_run:
        log.info("*** DRY-RUN mode – no API writes will occur ***")

    sys.exit(asyncio.run(_run(cfg, dry_run=args.dry_run)))


if __name__ == "__main__":
    main()
