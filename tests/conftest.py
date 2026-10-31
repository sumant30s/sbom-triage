import json

import pytest

from sbom_triage.demo import DEMO_SBOM


@pytest.fixture
def demo_bytes():
    return json.dumps(DEMO_SBOM).encode()
