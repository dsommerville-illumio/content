"""Test file for Illumio Integration."""

import io
import json
import pytest
from CommonServerPython import *  # noqa


@pytest.fixture
def mock_client():
    """Mock a client object with required data to mock."""
    from IllumioCore import IllumioClient

    client = IllumioClient(
        base_url="https://127.0.0.1:8443",
        org_id=1,
        api_user="dummy",
        api_key="dummy-1",
        proxy={}
    )
    return client


def util_load_json(path):
    """Load a JSON file to python dictionary."""
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_test_module(requests_mock, mock_client):
    """
    Test case scenario for successful execution of test_module.

    Given:
       - mocked client
    When:
       - Calling `test_module` function
    Then:
       - Returns an ok message
    """
    from IllumioCore import test_module
    requests_mock.get("https://127.0.0.1:8443/api/v2/orgs/1/workloads",
                      status_code=200, json={})
    assert test_module(mock_client) == 'ok'
