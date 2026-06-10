"""Apify — broker profiles via the TruePeopleSearch Contact Finder actor.

Requires APIFY_API_TOKEN + APIFY_ACTOR_ID. The actor needs a name AND an address
(city/state/zip) together, so it returns nothing without a location.
"""

import structlog
from apify_client import ApifyClient

from eidolon import config
from eidolon.tools.base import Tool
from eidolon.tools.broker_scan import (
    BrokerProfile,
    BrokerProfilesOutput,
    BrokerScanInput,
)


class Apify(Tool[BrokerScanInput, BrokerProfilesOutput]):
    name = "apify"
    input_type = "name"
    input_schema = BrokerScanInput
    output_schema = BrokerProfilesOutput

    def available(self) -> bool:
        return bool(config.get("APIFY_API_TOKEN"))

    def _run(
        self, inp: BrokerScanInput, log: structlog.stdlib.BoundLogger
    ) -> BrokerProfilesOutput:
        address = ", ".join(x for x in (inp.city, inp.state, inp.zip_code) if x)
        if inp.input_type != "name" or not address:
            log.info("skipped — actor requires a name and an address/state")
            return BrokerProfilesOutput()

        run_input = {
            "scrapFlyApiKey": config.get("SCRAPFLY_API_KEY"),
            "searches": [],
            "name": inp.value,
            "address": address,
            "maxConcurrency": 3,
        }
        client = ApifyClient(config.get("APIFY_API_TOKEN"))
        # ApifyClient.call() returns a pydantic Run object (or None), NOT a dict.
        run = client.actor(config.get("APIFY_ACTOR_ID")).call(run_input=run_input)
        if run is None or not run.default_dataset_id:
            log.warning("apify returned no dataset")
            return BrokerProfilesOutput()

        profiles = [
            BrokerProfile(
                broker_name=item.get("source", "Unknown"),
                broker_domain=item.get("domain", ""),
                source="apify",
                profile_url=item.get("profileUrl"),
                data_found=item.get("dataFound", []),
                confidence="high" if item.get("exactMatch") else "medium",
                optout_url=item.get("optoutUrl", ""),
            )
            for item in client.dataset(run.default_dataset_id).iterate_items()
        ]
        log.info("ok", profiles=len(profiles))
        return BrokerProfilesOutput(profiles=profiles, count=len(profiles))
