"""Test file for Illumio Integration."""

import io
import json
import pytest
from illumio import PolicyComputeEngine, IllumioException
from CommonServerPython import *  # noqa
from IllumioCore import InvalidMultiSelectException, InvalidSingleSelectException, InvalidPortException, \
    VALID_POLICY_DECISIONS, VALID_PROTOCOLS


@pytest.fixture
def mock_client():
    """Mock a client object with required data to mock."""

    client = PolicyComputeEngine(url="https://127.0.0.1:8443", port=8443, org_id=1)
    client.set_credentials('dummy', 'dummy-1')

    return client


def util_load_json(path):
    """Load a JSON file to python dictionary."""
    with io.open(path, mode="r", encoding="utf-8") as f:
        return json.loads(f.read())


def test_test_module(requests_mock, mock_client):
    """
    Test case scenario for successful execution of test_module.

    Given:
       - mocked client.
    When:
       - Calling `test_module` function.
    Then:
       - Returns an ok message.
    """
    from IllumioCore import test_module
    requests_mock.get("https://127.0.0.1:8443/api/v2/health",
                      status_code=200, json={})
    assert test_module(mock_client) == "ok"


@pytest.mark.parametrize("args, err_msg", [
    ({"port": "", "protocol": "tcp", 'start_time': '2022-07-17T12:58:33.528Z', 'end_time': "2022-07-18T12:58:33.529Z",
      'policy_decisions': ['potentially_blocked']},
     "{} is a required parameter. Please provide correct value.".format('port')),
    ({"port": "dummy", "protocol": "tcp", 'start_time': '2022-07-17T12:58:33.528Z',
      'end_time': "2022-07-18T12:58:33.529Z", 'policy_decisions': ['potentially_blocked']},
     '"dummy" is not a valid number'),
    ({"port": -300, "protocol": "tcp", 'start_time': '2022-07-17T12:58:33.528Z',
      'end_time': "2022-07-18T12:58:33.529Z", 'policy_decisions': ['potentially_blocked']},
     "{} is an invalid value for port. Value must be in 1 to 65535.".format(-300)),
    ({"port": 8443, "protocol": "tcp", 'start_time': '2022-07-17T12:58:33.528Z',
      'end_time': "2022-07-18T12:58:33.529Z", 'policy_decisions': ['dummy']},
     "Invalid value for {}. Possible comma separated values are {}.".format('policy_decisions',
                                                                            VALID_POLICY_DECISIONS)),
    ({"port": 8443, "protocol": "dummy", 'start_time': '2022-07-17T12:58:33.528Z',
      'end_time': "2022-07-18T12:58:33.529Z", 'policy_decisions': ['potentially_blocked']},
     "{} is an invalid value for {}. Possible values are: {}.".format('dummy', 'protocol', VALID_PROTOCOLS))
])
def test_illumio_traffic_analysis_command_for_invalid_arguments(args, err_msg, mock_client):
    """
    Test case scenario for execution of illumio-traffic-analysis-command when invalid argument provided.

    Given:
        - command arguments for illumio_traffic_analysis_command
    When:
        - Calling `illumio_traffic_analysis_command` function
    Then:
        - Returns a valid error message
    """
    from IllumioCore import illumio_traffic_analysis_command
    with pytest.raises((ValueError, IllumioException, InvalidPortException, InvalidSingleSelectException,
                        InvalidMultiSelectException)) as err:
        illumio_traffic_analysis_command(mock_client, args)
    assert str(err.value) == err_msg


def test_illumio_traffic_analysis_success(requests_mock, mock_client):
    """
    Test case scenario for successful execution of illumio_traffic_analysis_command function.

    Given:
        - command arguments for illumio_traffic_analysis
    When:
        - Calling `illumio_traffic_analysis_Command` function
    Then:
        - Returns a valid output
    """
    from IllumioCore import illumio_traffic_analysis_command

    args = {'port': 8443, 'protocol': "tcp", 'policy_decisions': 'potentially_blocked',
            'start_time': "2022-07-17T12:58:33.528Z", 'end_time': "2022-07-18T12:58:33.529Z"}

    json_data = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                            "test_data/traffic_analysis_success_response.json"))

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "./test_data/traffic_analysis_success_hr.md")) as file:
        hr_output = file.read()

    json_data_get = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                "test_data/traffic_analysis_get_response.json"))

    json_download_data = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                     "test_data/traffic_analysis_download_data.json"))

    requests_mock.post("https://127.0.0.1:8443/api/v2/orgs/1/traffic_flows/async_queries",
                       json=json_data)

    requests_mock.get(
        "https://127.0.0.1:8443/api/v2/orgs/1/traffic_flows/async_queries/a89cb6ff-980f-46bf-b715-e021ce55c0db",
        json=json_data_get)

    requests_mock.get(
        "https://127.0.0.1:8443/api/v2/orgs/1/traffic_flows/async_queries/d99b77b2-9ad4-4fe6-ac17-09ed634a47a4/download",
        json=json_download_data)

    response = illumio_traffic_analysis_command(mock_client, args)

    assert response.outputs_prefix == "Illumio.TrafficFlows"
    assert response.raw_response == json_download_data
    assert response.outputs == json_download_data
    assert response.outputs_key_field == 'href'
    assert response.readable_output == hr_output
