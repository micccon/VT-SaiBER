from __future__ import annotations

import pytest

from tests.db_tests.live_helpers import CVEClient, step


@pytest.mark.asyncio
@pytest.mark.live
@pytest.mark.cve
async def test_live_cve_client_resolves_known_identifier() -> None:
    step("Querying NVD/CISA live for a known CVE identifier")
    client = CVEClient()
    results = await client.search(
        query="CVE-2011-2523",
        known_cves=["CVE-2011-2523"],
        max_results=3,
    )
    assert results
    top = results[0]
    print(
        f"[live-cve] top={top.identifier} score={top.score} "
        f"severity={top.metadata.get('severity')} known_exploited={top.metadata.get('known_exploited')}"
    )
    assert top.identifier == "CVE-2011-2523"
    assert "nvd.nist.gov" in top.reference.lower()


@pytest.mark.asyncio
@pytest.mark.live
@pytest.mark.cve
async def test_live_cve_client_resolves_product_version_clue() -> None:
    step("Querying NVD/CISA live from a product/version clue")
    client = CVEClient()
    results = await client.search(
        query="Research exploit path for ftp service version vsftpd 2.3.4",
        service_clues=["ftp vsftpd 2.3.4 vsFTPd 2.3.4"],
        max_results=5,
    )
    assert results
    identifiers = [item.identifier for item in results]
    print(f"[live-cve] product/version ids={identifiers}")
    assert "CVE-2011-2523" in identifiers
