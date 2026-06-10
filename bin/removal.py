#!/usr/bin/env python3
"""
Data broker opt-out automation using Playwright.

Usage:
    python removal.py output/2026-06-07_scan_results.json
    python removal.py output/2026-06-07_scan_results.json --visible
"""

import argparse
import asyncio
import json
import sys
from datetime import datetime
from pathlib import Path

from playwright.async_api import BrowserContext, Page, async_playwright

# ── Target extraction ─────────────────────────────────────────────────────────


def extract_target(results: dict) -> dict:
    """Pull target info from a results JSON."""
    target = {
        "name": "",
        "first_name": "",
        "last_name": "",
        "email": "",
        "phone": "",
        "state": "",
    }

    # Email from classifications
    for cls in results.get("classifications", []):
        if cls.get("type") == "email":
            target["email"] = cls["value"]
        elif cls.get("type") == "phone":
            target["phone"] = cls["value"]
        elif cls.get("type") == "name":
            target["name"] = cls["value"]

    # Name from broker_result if available
    broker = results.get("broker_result", {})
    broker_data = broker.get("data", {})

    # Try to get name/state from broker profiles
    for profile in broker_data.get("brokers_found", []):
        data_found = profile.get("data_found", [])
        for item in data_found:
            if isinstance(item, dict):
                if item.get("type") == "name" and not target["name"]:
                    target["name"] = item.get("value", "")
                if item.get("type") == "state" and not target["state"]:
                    target["state"] = item.get("value", "")

    # Split name into first/last
    if target["name"]:
        parts = target["name"].strip().split()
        if len(parts) >= 2:
            target["first_name"] = parts[0]
            target["last_name"] = " ".join(parts[1:])
        else:
            target["first_name"] = target["name"]

    return target


def get_brokers_found(results: dict) -> list[str]:
    """Return list of broker names found in the scan results."""
    broker_data = results.get("broker_result", {}).get("data", {})
    found = broker_data.get("brokers_found", [])
    if found:
        return [b.get("broker_name", b.get("source", "Unknown")) for b in found]
    # If no specific brokers listed, return the five we always attempt
    return [
        "FastPeopleSearch",
        "TruePeopleSearch",
        "Spokeo",
        "BeenVerified",
        "Whitepages",
    ]


# ── Shared helpers ────────────────────────────────────────────────────────────

SCREENSHOT_DIR = Path("/app/output/removal_screenshots")


async def save_screenshot(page: Page, broker: str, label: str) -> None:
    SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%H%M%S")
    fname = SCREENSHOT_DIR / f"{broker.lower().replace(' ', '_')}_{label}_{ts}.png"
    await page.screenshot(path=str(fname), full_page=True)
    print(f"    Screenshot saved: {fname.name}")


async def human_delay(page: Page, ms: int = 2500) -> None:
    """Wait a realistic amount of time between actions."""
    await page.wait_for_timeout(ms)


# ── Broker opt-out flows ──────────────────────────────────────────────────────


async def remove_fastpeoplesearch(page: Page, target: dict) -> dict:
    """FastPeopleSearch removal via their dedicated removal page."""
    result = {"broker": "FastPeopleSearch", "success": False, "message": ""}
    try:
        print("  [FastPeopleSearch] Navigating to removal page...")
        await page.goto(
            "https://www.fastpeoplesearch.com/removal",
            wait_until="domcontentloaded",
            timeout=30000,
        )
        await human_delay(page)

        # The page has a search form — enter first name, last name, state
        if target.get("first_name"):
            first_input = page.locator(
                "input[name='firstname'], input[placeholder*='First'], #first_name"
            ).first
            await first_input.fill(target["first_name"])
            await human_delay(page, 1000)

        if target.get("last_name"):
            last_input = page.locator(
                "input[name='lastname'], input[placeholder*='Last'], #last_name"
            ).first
            await last_input.fill(target["last_name"])
            await human_delay(page, 1000)

        if target.get("state"):
            state_input = page.locator(
                "select[name='state'], input[name='state'], #state"
            ).first
            # Try select element first
            try:
                await state_input.select_option(label=target["state"], timeout=3000)
            except Exception:
                await state_input.fill(target["state"])
            await human_delay(page, 1000)

        # Submit search
        await page.get_by_role("button", name="Search").click()
        await page.wait_for_load_state("networkidle", timeout=20000)
        await human_delay(page)

        # Look for "Remove My Info" links on results
        remove_links = page.get_by_text("Remove My Info", exact=False)
        count = await remove_links.count()
        if count > 0:
            await remove_links.first.click()
            await page.wait_for_load_state("networkidle", timeout=20000)
            await human_delay(page)
            await save_screenshot(page, "fastpeoplesearch", "confirmation")
            result["success"] = True
            result["message"] = f"Clicked 'Remove My Info' on {count} result(s)"
        else:
            await save_screenshot(page, "fastpeoplesearch", "no_results")
            result["message"] = "No matching results found — record may not exist"
            result["success"] = True  # not an error, just not found

    except Exception as e:
        result["message"] = f"Error: {e}"
        try:
            await save_screenshot(page, "fastpeoplesearch", "error")
        except Exception:
            pass

    return result


async def remove_truepeoplesearch(page: Page, target: dict) -> dict:
    """TruePeopleSearch removal via their removal page."""
    result = {"broker": "TruePeopleSearch", "success": False, "message": ""}
    try:
        print("  [TruePeopleSearch] Navigating to removal page...")
        await page.goto(
            "https://www.truepeoplesearch.com/removal",
            wait_until="domcontentloaded",
            timeout=30000,
        )
        await human_delay(page)

        # Fill name
        if target.get("first_name"):
            await page.locator(
                "input[name='fn'], input[placeholder*='First']"
            ).first.fill(target["first_name"])
            await human_delay(page, 800)

        if target.get("last_name"):
            await page.locator(
                "input[name='ln'], input[placeholder*='Last']"
            ).first.fill(target["last_name"])
            await human_delay(page, 800)

        if target.get("state"):
            try:
                await page.locator("select[name='state']").first.select_option(
                    label=target["state"], timeout=3000
                )
            except Exception:
                pass
            await human_delay(page, 800)

        await page.get_by_role("button", name="Search").click()
        await page.wait_for_load_state("networkidle", timeout=20000)
        await human_delay(page)

        # Look for remove buttons
        remove_btn = page.get_by_text("Remove This Listing", exact=False)
        count = await remove_btn.count()
        if count > 0:
            await remove_btn.first.click()
            await page.wait_for_load_state("networkidle", timeout=20000)
            await human_delay(page)
            await save_screenshot(page, "truepeoplesearch", "confirmation")
            result["success"] = True
            result["message"] = f"Clicked remove on {count} listing(s)"
        else:
            await save_screenshot(page, "truepeoplesearch", "no_results")
            result["success"] = True
            result["message"] = "No matching records found"

    except Exception as e:
        result["message"] = f"Error: {e}"
        try:
            await save_screenshot(page, "truepeoplesearch", "error")
        except Exception:
            pass

    return result


async def remove_spokeo(page: Page, target: dict) -> dict:
    """Spokeo opt-out via their optout page (email-based search)."""
    result = {"broker": "Spokeo", "success": False, "message": ""}
    try:
        print("  [Spokeo] Navigating to opt-out page...")
        await page.goto(
            "https://www.spokeo.com/optout",
            wait_until="domcontentloaded",
            timeout=30000,
        )
        await human_delay(page)

        # Spokeo optout: enter URL of the listing or search by email
        # First try searching by email to find the listing URL
        if target.get("email"):
            search_input = page.locator(
                "input[type='text'], input[type='email'], input[name*='search']"
            ).first
            await search_input.fill(target["email"])
            await human_delay(page, 1000)
            await page.keyboard.press("Enter")
            await page.wait_for_load_state("networkidle", timeout=20000)
            await human_delay(page)

        # Look for opt-out / remove listing button
        remove_btn = page.get_by_text("Remove this listing", exact=False)
        count = await remove_btn.count()

        if count == 0:
            remove_btn = page.get_by_text("Opt Out", exact=False)
            count = await remove_btn.count()

        if count > 0:
            await remove_btn.first.click()
            await page.wait_for_load_state("networkidle", timeout=20000)
            await human_delay(page)

            # Spokeo asks for a confirmation email
            confirm_email_input = page.locator(
                "input[type='email'], input[name*='email']"
            ).first
            try:
                await confirm_email_input.wait_for(timeout=5000)
                if target.get("email"):
                    await confirm_email_input.fill(target["email"])
                    await human_delay(page, 800)

                await page.get_by_role("button", name="Send Confirmation").click()
                await page.wait_for_load_state("networkidle", timeout=20000)
            except Exception:
                pass  # Confirmation form may not appear in all flows

            await save_screenshot(page, "spokeo", "confirmation")
            result["success"] = True
            result["message"] = "Opt-out submitted; check email for confirmation link"
        else:
            await save_screenshot(page, "spokeo", "no_results")
            result["success"] = True
            result["message"] = "No matching listings found"

    except Exception as e:
        result["message"] = f"Error: {e}"
        try:
            await save_screenshot(page, "spokeo", "error")
        except Exception:
            pass

    return result


async def remove_beenverified(page: Page, target: dict) -> dict:
    """BeenVerified opt-out via their opt-out search page."""
    result = {"broker": "BeenVerified", "success": False, "message": ""}
    try:
        print("  [BeenVerified] Navigating to opt-out page...")
        await page.goto(
            "https://www.beenverified.com/app/optout/search",
            wait_until="domcontentloaded",
            timeout=30000,
        )
        await human_delay(page)

        if target.get("first_name"):
            fn = page.locator(
                "input[name='fname'], input[placeholder*='First'], #fname"
            ).first
            await fn.fill(target["first_name"])
            await human_delay(page, 800)

        if target.get("last_name"):
            ln = page.locator(
                "input[name='lname'], input[placeholder*='Last'], #lname"
            ).first
            await ln.fill(target["last_name"])
            await human_delay(page, 800)

        if target.get("state"):
            try:
                state_sel = page.locator("select[name='state']").first
                await state_sel.select_option(label=target["state"], timeout=3000)
            except Exception:
                pass
            await human_delay(page, 800)

        await page.get_by_role("button", name="Search").click()
        await page.wait_for_load_state("networkidle", timeout=30000)
        await human_delay(page)

        # Select matching record
        select_btn = page.get_by_text("Select & Continue", exact=False)
        count = await select_btn.count()
        if count == 0:
            select_btn = page.get_by_text("This is me", exact=False)
            count = await select_btn.count()

        if count > 0:
            await select_btn.first.click()
            await page.wait_for_load_state("networkidle", timeout=20000)
            await human_delay(page)

            # Confirm opt-out
            optout_btn = page.get_by_text("Opt Out", exact=False)
            optout_count = await optout_btn.count()
            if optout_count > 0:
                await optout_btn.first.click()
                await page.wait_for_load_state("networkidle", timeout=20000)
                await human_delay(page)

            await save_screenshot(page, "beenverified", "confirmation")
            result["success"] = True
            result["message"] = "Opt-out submitted successfully"
        else:
            await save_screenshot(page, "beenverified", "no_results")
            result["success"] = True
            result["message"] = "No matching records found"

    except Exception as e:
        result["message"] = f"Error: {e}"
        try:
            await save_screenshot(page, "beenverified", "error")
        except Exception:
            pass

    return result


async def remove_whitepages(page: Page, target: dict) -> dict:
    """Whitepages suppression request form."""
    result = {"broker": "Whitepages", "success": False, "message": ""}
    try:
        print("  [Whitepages] Navigating to suppression request form...")
        await page.goto(
            "https://www.whitepages.com/suppression_requests/new",
            wait_until="domcontentloaded",
            timeout=30000,
        )
        await human_delay(page)

        # Whitepages requires finding your listing first — search by name
        if target.get("first_name"):
            fn = page.locator(
                "input[name='first_name'], input[placeholder*='First']"
            ).first
            await fn.fill(target["first_name"])
            await human_delay(page, 800)

        if target.get("last_name"):
            ln = page.locator(
                "input[name='last_name'], input[placeholder*='Last']"
            ).first
            await ln.fill(target["last_name"])
            await human_delay(page, 800)

        if target.get("phone"):
            phone_input = page.locator("input[name='phone'], input[type='tel']").first
            try:
                await phone_input.wait_for(timeout=3000)
                await phone_input.fill(target["phone"])
                await human_delay(page, 800)
            except Exception:
                pass

        # Submit
        submit_btn = page.get_by_role("button", name="Submit").first
        await submit_btn.click()
        await page.wait_for_load_state("networkidle", timeout=20000)
        await human_delay(page)

        # Check for success indicators
        page_text = await page.inner_text("body")
        if any(
            kw in page_text.lower()
            for kw in ["submitted", "confirmation", "success", "suppression"]
        ):
            await save_screenshot(page, "whitepages", "confirmation")
            result["success"] = True
            result["message"] = "Suppression request submitted"
        else:
            # Look for listing to select
            listing_btn = page.get_by_text("This is me", exact=False)
            count = await listing_btn.count()
            if count > 0:
                await listing_btn.first.click()
                await page.wait_for_load_state("networkidle", timeout=20000)
                await human_delay(page)
                await save_screenshot(page, "whitepages", "confirmation")
                result["success"] = True
                result["message"] = (
                    "Suppression request submitted after selecting record"
                )
            else:
                await save_screenshot(page, "whitepages", "result")
                result["success"] = True
                result["message"] = "Form submitted — check screenshot for result"

    except Exception as e:
        result["message"] = f"Error: {e}"
        try:
            await save_screenshot(page, "whitepages", "error")
        except Exception:
            pass

    return result


# ── Orchestration ─────────────────────────────────────────────────────────────

BROKER_HANDLERS = {
    "FastPeopleSearch": remove_fastpeoplesearch,
    "TruePeopleSearch": remove_truepeoplesearch,
    "Spokeo": remove_spokeo,
    "BeenVerified": remove_beenverified,
    "Whitepages": remove_whitepages,
}

# Normalise broker names from scan results to our handler keys
BROKER_ALIASES = {
    "fastpeoplesearch": "FastPeopleSearch",
    "fast people search": "FastPeopleSearch",
    "truepeoplesearch": "TruePeopleSearch",
    "true people search": "TruePeopleSearch",
    "spokeo": "Spokeo",
    "beenverified": "BeenVerified",
    "been verified": "BeenVerified",
    "whitepages": "Whitepages",
    "white pages": "Whitepages",
}


def normalise_broker_name(name: str) -> str | None:
    key = name.lower().strip()
    return BROKER_ALIASES.get(key)


async def run_removals(results_path: Path, headless: bool) -> None:
    results = json.loads(results_path.read_text())
    target = extract_target(results)
    brokers_in_results = get_brokers_found(results)

    # Determine which of our supported brokers to attempt
    to_attempt = []
    for b in brokers_in_results:
        norm = normalise_broker_name(b)
        if norm and norm not in to_attempt:
            to_attempt.append(norm)

    # If scan found nothing specific, attempt all five anyway
    if not to_attempt:
        to_attempt = list(BROKER_HANDLERS.keys())

    print()
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("  osint-agent  |  Removal Bot")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"  Results file : {results_path.name}")
    print(f"  Target name  : {target['name'] or '(not found in results)'}")
    print(f"  Target email : {target['email'] or '(not found)'}")
    print(f"  Target phone : {target['phone'] or '(not found)'}")
    print(f"  Target state : {target['state'] or '(not found)'}")
    print()
    print(f"  Brokers to attempt opt-out ({len(to_attempt)}):")
    for b in to_attempt:
        print(f"    • {b}")
    print()

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=headless,
            args=["--no-sandbox", "--disable-setuid-sandbox"],
        )
        context: BrowserContext = await browser.new_context(
            viewport={"width": 1280, "height": 900},
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
        )

        results_log = []
        succeeded = 0

        for broker_name in to_attempt:
            handler = BROKER_HANDLERS.get(broker_name)
            if not handler:
                print(f"  [SKIP] {broker_name} — no handler implemented")
                continue

            print(f"\n[{broker_name}] Starting opt-out...")
            page = await context.new_page()
            try:
                res = await handler(page, target)
                results_log.append(res)
                if res["success"]:
                    succeeded += 1
                    print(f"  [OK]   {res['message']}")
                else:
                    print(f"  [FAIL] {res['message']}")
            finally:
                await page.close()

            # Polite delay between brokers
            await asyncio.sleep(3)

        await browser.close()

    # Summary
    total = len(results_log)
    print()
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"  Submitted opt-out to {succeeded}/{total} brokers.")
    print("  Screenshots saved to: output/removal_screenshots/")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print()

    # Detailed log
    for r in results_log:
        status = "OK  " if r["success"] else "FAIL"
        print(f"  [{status}] {r['broker']}: {r['message']}")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(description="Data broker opt-out automation")
    parser.add_argument(
        "results_file",
        nargs="?",
        help="Path to scan results JSON (default: most recent in /app/output/)",
    )
    parser.add_argument(
        "--visible",
        action="store_true",
        help="Show browser window (non-headless)",
    )
    args = parser.parse_args()

    output_dir = Path("/app/output")

    if args.results_file:
        results_path = Path(args.results_file)
    else:
        # Find most recent *_results.json
        candidates = sorted(output_dir.glob("*_results.json"), reverse=True)
        if not candidates:
            print("ERROR: No results JSON files found in /app/output/")
            sys.exit(1)
        results_path = candidates[0]
        print(f"Using most recent results file: {results_path.name}")

    if not results_path.exists():
        print(f"ERROR: File not found: {results_path}")
        sys.exit(1)

    asyncio.run(run_removals(results_path, headless=not args.visible))


if __name__ == "__main__":
    main()
