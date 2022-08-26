"""Test file for Illumio Integration."""

import io

import pytest

from CommonServerPython import *  # noqa
from IllumioCore import *

""" CONSTANTS """

DIRECTORY_PATH = os.path.dirname(os.path.realpath(__file__))
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


@pytest.mark.parametrize(
    "args, err_msg, err_type",
    [
        (
                {
                    "port": "",
                    "protocol": "tcp",
                    "start_time": "2022-07-17T12:58:33.528Z",
                    "end_time": "2022-07-18T12:58:33.529Z",
                    "policy_decisions": ["potentially_blocked"],
                },
                MISSING_REQUIRED_PARAM_EXCEPTION_MESSAGE.format("port"),
                ValueError,
        ),
        (
                {
                    "port": "dummy",
                    "protocol": "tcp",
                    "start_time": "2022-07-17T12:58:33.528Z",
                    "end_time": "2022-07-18T12:58:33.529Z",
                    "policy_decisions": ["potentially_blocked"],
                },
                '"dummy" is not a valid number',
                ValueError,
        ),
        (
                {
                    "port": -300,
                    "protocol": "tcp",
                    "start_time": "2022-07-17T12:58:33.528Z",
                    "end_time": "2022-07-18T12:58:33.529Z",
                    "policy_decisions": ["potentially_blocked"],
                },
                INVALID_PORT_NUMBER_EXCEPTION_MESSAGE.format(-300),
                InvalidValueError,
        ),
        (
                {
                    "port": 8443,
                    "protocol": "tcp",
                    "start_time": "2022-07-17T12:58:33.528Z",
                    "end_time": "2022-07-18T12:58:33.529Z",
                    "policy_decisions": ["dummy"],
                },
                "Invalid value for {}. Possible comma separated values are {}.".format(
                    "policy_decisions", VALID_POLICY_DECISIONS
                ),
                InvalidValueError,
        ),
        (
                {
                    "port": 8443,
                    "protocol": "dummy",
                    "start_time": "2022-07-17T12:58:33.528Z",
                    "end_time": "2022-07-18T12:58:33.529Z",
                    "policy_decisions": ["potentially_blocked"],
                },
                "{} is an invalid value for {}. Possible values are: {}.".format("dummy", "protocol", VALID_PROTOCOLS),
                InvalidValueError,
        ),
    ],
)
def test_traffic_analysis_command_for_invalid_arguments(args, err_msg, err_type, mock_client):
    """
    Test case scenario for execution of traffic-analysis-command when invalid argument provided.

    Given:
        - command arguments for traffic_analysis_command
    When:
        - Calling `traffic_analysis_command` function
    Then:
        - Returns a valid error message
    """
    from IllumioCore import traffic_analysis_command

    with pytest.raises(err_type) as err:
        traffic_analysis_command(mock_client, args)
        assert str(err.value) == err_msg


def test_traffic_analysis_success(requests_mock, mock_client):
    """
    Test case scenario for successful execution of traffic-analysis-command function.

    Given:
        - command arguments for traffic_analysis
    When:
        - Calling `traffic_analysis_Command` function
    Then:
        - Returns a valid raw_response.
    """
    args = {
        "port": 8443,
        "protocol": "tcp",
        "policy_decisions": "potentially_blocked",
        "start_time": "2022-07-17T12:58:33.528Z",
        "end_time": "2022-07-18T12:58:33.529Z",
    }

    json_data = util_load_json(os.path.join(DIRECTORY_PATH, "test_data/traffic_analysis_success_response.json"))

    json_data_get = util_load_json(os.path.join(DIRECTORY_PATH, "test_data/traffic_analysis_get_response.json"))

    json_download_data = util_load_json(os.path.join(DIRECTORY_PATH, "test_data/traffic_analysis_download_data.json"))

    requests_mock.post("https://127.0.0.1:8443/api/v2/orgs/1/traffic_flows/async_queries", json=json_data)

    requests_mock.get(
        "https://127.0.0.1:8443/api/v2/orgs/1/traffic_flows/async_queries/a89cb6ff-980f-46bf-b715-e021ce55c0db",
        json=json_data_get,
    )

    requests_mock.get(
        "https://127.0.0.1:8443/api/v2/orgs/1/traffic_flows/async_queries/d99b77b2-9ad4-4fe6-ac17-09ed634a47a4/download",
        json=json_download_data,
    )

    response = traffic_analysis_command(mock_client, args)

    assert response.raw_response == json_download_data


def test_traffic_analysis_human_readable():
    """
    Test case scenario for successful execution of traffic-analysis-command function.

    Given:
        - command arguments for traffic_analysis
    When:
        - Calling `traffic_analysis_Command` function
    Then:
        - Returns a valid human-readable.
    """

    json_download_data = util_load_json(os.path.join(DIRECTORY_PATH, "test_data/traffic_analysis_download_data.json"))

    with open(os.path.join(DIRECTORY_PATH, "./test_data/traffic_analysis_success_hr.md")) as file:
        hr_output = file.read()

    protocol = "tcp"

    response = prepare_traffic_analysis_output(json_download_data, protocol)
    assert response == hr_output


def test_virtual_service_create_command_for_success(requests_mock, mock_client):
    """Test case scenario for execution of virtual-service-create-command when valid and all arguments are provided.

    Given:
        - virtual_service_create_command function and mock_client to call the function.
    When:
        - Valid name, port, and protocol are provided in the command argument.
    Then:
        - Should return proper raw_response.
    """
    create_virtual_service_expected_resp = util_load_json(
        os.path.join(DIRECTORY_PATH, "test_data/create_virtual_service_success_response.json")
    )

    requests_mock.post(VIRTUAL_SERVICE_URL, json=create_virtual_service_expected_resp)
    resp = virtual_service_create_command(
        mock_client, {"name": "test_create_virtual_service", "port": 3000, "protocol": "tcp"})
    assert resp.raw_response == create_virtual_service_expected_resp


def test_virtual_service_create_command_for_human_readable():
    """Test case scenario for execution of virtual-service-create-command when valid and all arguments are provided.

    Given:
        - virtual_service_create_command function and mock_client to call the function.
    When:
        - Valid name, port, and protocol are provided in the command argument.
    Then:
        - Should return proper raw_response.
    """
    create_virtual_service_expected_resp = util_load_json(
        os.path.join(DIRECTORY_PATH, "test_data/create_virtual_service_success_response.json")
    )

    with open(os.path.join(DIRECTORY_PATH, "test_data/create_virtual_service_success_response_hr.md")) as f:
        expected_hr_output = f.read()

    response = prepare_virtual_service_output(create_virtual_service_expected_resp)
    assert response == expected_hr_output


def test_virtual_service_create_command_for_success_with_protocol_as_udp(requests_mock, mock_client):
    """Test case scenario for execution of virtual-service-create-command with protocol as udp.

    Given:
        - virtual_service_create_command function and mock_client to call the function.
    When:
        - Valid name, port, and protocol are provided in the command argument.
    Then:
        - Should return raw_response.
    """
    create_virtual_service_expected_resp = util_load_json(
        os.path.join(DIRECTORY_PATH, "test_data/create_virtual_service_success_response_protocol_as_udp.json")
    )
    requests_mock.post(VIRTUAL_SERVICE_URL, json=create_virtual_service_expected_resp)
    resp = virtual_service_create_command(mock_client, {"name": "test_create_virtual_service", "port": "3000"})

    assert resp.raw_response == create_virtual_service_expected_resp


def test_virtual_service_create_command_for_human_readable_with_protocol_as_udp():
    """Test case scenario for execution of virtual-service-create-command with protocol as udp.

    Given:
        - virtual_service_create_command function and mock_client to call the function.
    When:
        - Valid name, port, and protocol are provided in the command argument.
    Then:
        - Should return proper human-readable string.
    """
    create_virtual_service_expected_resp = util_load_json(
        os.path.join(DIRECTORY_PATH, "test_data/create_virtual_service_success_response_protocol_as_udp.json")
    )

    with open(
            os.path.join(DIRECTORY_PATH, "test_data/create_virtual_service_success_response_protocol_as_udp_hr.md")
    ) as f:
        expected_hr_output = f.read()

    response = prepare_virtual_service_output(create_virtual_service_expected_resp)
    assert response == expected_hr_output


def test_virtual_service_create_command_for_existing_virtual_service(requests_mock, mock_client):
    """Test case scenario for virtual-service-create-command with existing virtual service.

    Given:
        - virtual_service_create_command function and mock_client to call the function.
    When:
        - Virtual service already exists.
    Then:
        - Should raise exception with proper error message.
    """
    requests_mock.post(
        VIRTUAL_SERVICE_URL, status_code=406, json=[{"token": "name_must_be_unique", "message": "Name must be unique"}]
    )
    with pytest.raises(Exception) as error:
        virtual_service_create_command(mock_client, {"name": "test_virtual_service", "port": 3000, "protocol": "tcp"})
        assert str(error.value) == "406 Client Error: None for url: {}".format(VIRTUAL_SERVICE_URL)


@pytest.mark.parametrize(
    "err_msg, args, err_type",
    [
        (NOT_VALID_NUMBER_EXCEPTION_MESSAGE.format("port", "300i0"),
         {"name": "test", "port": "300i0", "protocol": "tcp"}, ValueError),
        (CONVERT_PROTOCOL_EXCEPTION_MESSAGE.format("tcpi"), {"name": "test", "port": "30000", "protocol": "tcpi"},
         InvalidValueError),
        (MISSING_REQUIRED_PARAM_EXCEPTION_MESSAGE.format("name"), {}, ValueError),
        (INVALID_PORT_NUMBER_CREATE_VIRTUAL_SERVICE_EXCEPTION_MESSAGE.format(65536), {"name": "test", "port": "65536"},
         InvalidValueError),
        (INVALID_PORT_NUMBER_CREATE_VIRTUAL_SERVICE_EXCEPTION_MESSAGE.format(0), {"name": "test", "port": "0"},
         InvalidValueError),
        (MISSING_REQUIRED_PARAM_EXCEPTION_MESSAGE.format("port"), {"name": "test"}, ValueError),
    ],
)
def test_virtual_service_create_command_when_invalid_arguments_provided(err_msg, args, err_type, mock_client):
    """Test case scenario for execution of virtual-service-create-command when invalid argument provided.

    Given:
        - command arguments for virtual-service-create-command.
    When:
        - Calling `virtual_service_create_command` function.
    Then:
        - Returns a valid error message.
    """
    with pytest.raises(err_type) as err:
        virtual_service_create_command(mock_client, args)
        assert str(err.value) == err_msg
