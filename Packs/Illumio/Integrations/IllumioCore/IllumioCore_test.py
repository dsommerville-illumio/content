"""Test file for Illumio Integration."""

import io
import json
import pytest
from illumio import PolicyComputeEngine, IllumioException
from CommonServerPython import *  # noqa
from IllumioCore import InvalidMultiSelectException, InvalidSingleSelectException, InvalidPortException, \
    VALID_POLICY_DECISIONS, VALID_PROTOCOLS


'''CONSTANTS'''

VIRTUAL_SERVICE_URL = "https://127.0.0.1:8443/api/v2/orgs/1/sec_policy/draft/virtual_services"
INVALID_PORT_NUMBER_CREATE_VIRTUAL_SERVICE_EXCEPTION_MESSAGE = (
    "{} is an invalid value for port. Value must be in 1 to 65535 or -1.")
INVALID_PORT_NUMBER_EXCEPTION_MESSAGE = "{} is an invalid value for port. Value must be in 1 to 65535."
CONVERT_PROTOCOL_EXCEPTION_MESSAGE = "{} is an invalid value for protocol. Possible values are: ['tcp', 'udp']."
MISSING_REQUIRED_PARAM_EXCEPTION_MESSAGE = "{} is a required parameter. Please provide correct value."
NOT_VALID_NUMBER_EXCEPTION_MESSAGE = 'Invalid number: "{}"="{}"'
INVALID_ENFORCEMENT_MODES_EXCEPTION_MESSAGE = "{} is an invalid enforcement mode."
INVALID_VISIBILITY_LEVEL_EXCEPTION_MESSAGE = "{} is an invalid visibility level."
INVALID_BOOLEAN_EXCEPTION_MESSAGE = "Argument does not contain a valid boolean-like value"
INVALID_MAX_RESULTS_EXCEPTION_MESSAGE = "{} is an invalid value for max results. Max results must be between 0 and 500"


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


def test_illumio_virtual_service_create_command_for_success_with_all_arguments(requests_mock, mock_client):
    """Test case scenario for execution of illumio-virtual-service-create-command when valid and all arguments are provided.

    Given:
        - illumio_virtual_service_create_command function and mock_client to call the function.
    When:
        - Valid name, port, and protocol are provided in the command argument.
    Then:
        - Should return proper human-readable string and context data.
    """
    from IllumioCore import illumio_virtual_service_create_command

    create_virtual_service_expected_resp = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)),
                     "test_data/create_virtual_service_success_response.json"))

    requests_mock.post(VIRTUAL_SERVICE_URL, json=create_virtual_service_expected_resp)
    resp = illumio_virtual_service_create_command(mock_client, {"name": "test_create_virtual_service", "port": 3000,
                                                                "protocol": "tcp"})
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/create_virtual_service_success_response_hr.md")) as f:
        expected_hr_output = f.read()

    assert resp.outputs == create_virtual_service_expected_resp
    assert resp.raw_response == create_virtual_service_expected_resp
    assert resp.readable_output == expected_hr_output
    assert resp.outputs_prefix == "Illumio.VirtualService"
    assert resp.outputs_key_field == "href"


def test_illumio_virtual_service_create_command_for_success_with_only_required_arguments(requests_mock, mock_client):
    """Test case scenario for execution of illumio-virtual-service-create-command with valid and only required arguments.

    Given:
        - illumio_virtual_service_create_command function and mock_client to call the function.
    When:
        - Valid name, port, and protocol are provided in the command argument.
    Then:
        - Should return proper human-readable string and context data.
    """
    from IllumioCore import illumio_virtual_service_create_command

    create_virtual_service_expected_resp = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)),
                     "test_data/create_virtual_service_success_response.json", ))
    requests_mock.post(VIRTUAL_SERVICE_URL, json=create_virtual_service_expected_resp)
    resp = illumio_virtual_service_create_command(mock_client, {"name": "test_create_virtual_service", "port": "3000"})
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/create_virtual_service_success_response_hr.md")) as f:
        expected_hr_output = f.read()

    assert resp.outputs == create_virtual_service_expected_resp
    assert resp.raw_response == create_virtual_service_expected_resp
    assert resp.readable_output == expected_hr_output
    assert resp.outputs_prefix == "Illumio.VirtualService"
    assert resp.outputs_key_field == "href"


def test_illumio_virtual_service_create_command_for_success_with_protocol_as_udp(requests_mock, mock_client):
    """Test case scenario for execution of illumio-virtual-service-create-command with protocol as udp.

    Given:
        - illumio_virtual_service_create_command function and mock_client to call the function.
    When:
        - Valid name, port, and protocol are provided in the command argument.
    Then:
        - Should return proper human-readable string and context data.
    """
    from IllumioCore import illumio_virtual_service_create_command

    create_virtual_service_expected_resp = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)),
                     "test_data/create_virtual_service_success_response_protocol_as_udp.json"))
    requests_mock.post(VIRTUAL_SERVICE_URL, json=create_virtual_service_expected_resp)
    resp = illumio_virtual_service_create_command(mock_client, {"name": "test_create_virtual_service", "port": "3000"})
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/create_virtual_service_success_response_protocol_as_udp_hr.md")) as f:
        expected_hr_output = f.read()

    assert resp.outputs == create_virtual_service_expected_resp
    assert resp.raw_response == create_virtual_service_expected_resp
    assert resp.readable_output == expected_hr_output
    assert resp.outputs_prefix == "Illumio.VirtualService"
    assert resp.outputs_key_field == "href"


def test_illumio_virtual_service_create_command_for_existing_virtual_service(requests_mock, mock_client, capfd):
    """Test case scenario for illumio-virtual-service-create-command with existing virtual service.

    Given:
        - illumio_virtual_service_create_command function and mock_client to call the function.
    When:
        - Virtual service already exists.
    Then:
        - Should raise exception with proper error message.
    """
    from IllumioCore import illumio_virtual_service_create_command

    requests_mock.post(VIRTUAL_SERVICE_URL, status_code=406,
                       json=[{"token": "name_must_be_unique", "message": "Name must be unique"}])
    with pytest.raises(Exception) as error:
        capfd.close()
        illumio_virtual_service_create_command(mock_client,
                                               {"name": "test_virtual_service", "port": 3000, "protocol": "tcp"})

    assert str(error.value) == "406 Client Error: None for url: {}".format(VIRTUAL_SERVICE_URL)


@pytest.mark.parametrize(
    "err_msg, args",
    [(NOT_VALID_NUMBER_EXCEPTION_MESSAGE.format("port", "300i0"), {"name": "test", "port": "300i0", "protocol": "tcp"}),
     (CONVERT_PROTOCOL_EXCEPTION_MESSAGE.format("tcpi"), {"name": "test", "port": "30000", "protocol": "tcpi"}),
     (MISSING_REQUIRED_PARAM_EXCEPTION_MESSAGE.format("name"), {}),
     (INVALID_PORT_NUMBER_CREATE_VIRTUAL_SERVICE_EXCEPTION_MESSAGE.format(65536), {"name": "test", "port": "65536"}),
     (INVALID_PORT_NUMBER_CREATE_VIRTUAL_SERVICE_EXCEPTION_MESSAGE.format(0), {"name": "test", "port": "0"}),
     (MISSING_REQUIRED_PARAM_EXCEPTION_MESSAGE.format("port"), {"name": "test"})]
)
def test_illumio_virtual_service_create_command_when_invalid_arguments_provided(err_msg, args, mock_client, capfd):
    """Test case scenario for execution of illumio-virtual-service-create-command when invalid argument provided.

    Given:
        - command arguments for illumio-virtual-service-create-command.
    When:
        - Calling `illumio_virtual_service_create_command` function.
    Then:
        - Returns a valid error message.
    """
    from IllumioCore import illumio_virtual_service_create_command

    with pytest.raises((ValueError, InvalidSingleSelectException)) as err:
        capfd.close()
        illumio_virtual_service_create_command(mock_client, args)

    assert str(err.value) == err_msg
