"""Test file for Illumio Integration."""

import io
import re

import pytest
import illumio
from illumio import TrafficFlow, ServiceBinding, Workload, IllumioApiException, PolicyVersion, PolicyComputeEngine, \
    VirtualService

from CommonServerPython import *  # noqa
from IllumioCore import test_module, InvalidValueError, VALID_POLICY_DECISIONS, VALID_PROTOCOLS, \
    traffic_analysis_command, prepare_traffic_analysis_output, virtual_service_create_command, \
    prepare_virtual_service_output, service_binding_create_command, prepare_service_binding_output, \
    object_provision_command, prepare_object_provision_output

""" CONSTANTS """

WORKLOAD_EXP_URL = "/orgs/1/workloads/dummy"
VIRTUAL_SERVICE_EXP_URL = "/orgs/1/sec_policy/active/virtual_services/dummy"
TEST_DATA_DIRECTORY = os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data")
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


@pytest.fixture(scope="module")
def traffic_analysis_create_success():
    """Retrieve the json response for traffic analysis."""
    return util_load_json(os.path.join(TEST_DATA_DIRECTORY, "traffic_analysis_download_data.json"))


@pytest.fixture(scope="module")
def traffic_analysis_create_success_hr():
    """Retrieve the human-readable for traffic analysis."""
    with open(os.path.join(TEST_DATA_DIRECTORY, "traffic_analysis_success_hr.md")) as file:
        hr_output = file.read()
    return hr_output


@pytest.fixture(scope="module")
def virtual_service_create_success():
    """Retrieve the json response for virtual service."""
    return util_load_json(os.path.join(TEST_DATA_DIRECTORY, "create_virtual_service_success_response.json"))


@pytest.fixture(scope="module")
def virtual_service_create_success_udp():
    """Retrieve the json response for virtual service for UDP protocol."""
    return util_load_json(
        os.path.join(TEST_DATA_DIRECTORY, "create_virtual_service_success_response_protocol_as_udp.json")
    )


@pytest.fixture(scope="module")
def virtual_service_success_hr():
    """Retrieve the human-readable response for virtual service."""
    with open(os.path.join(TEST_DATA_DIRECTORY, "create_virtual_service_success_response_hr.md")) as f:
        expected_hr_output = f.read()
    return expected_hr_output


@pytest.fixture(scope="module")
def virtual_service_success_udp_hr():
    """Retrieve the human-readable response for virtual service for UDP protocol."""
    with open(
            os.path.join(TEST_DATA_DIRECTORY, "create_virtual_service_success_response_protocol_as_udp_hr.md")
    ) as f:
        expected_hr_output = f.read()
    return expected_hr_output


@pytest.fixture(scope="module")
def service_binding_success():
    """Retrieve the json response for service binding."""
    return util_load_json(
        os.path.join(TEST_DATA_DIRECTORY, "create_service_binding_success_resp.json")
    )


@pytest.fixture(scope="module")
def service_binding_success_hr():
    """Retrieve the human-readable for service binding."""
    with open(
            os.path.join(
                TEST_DATA_DIRECTORY, "create_service_binding_success_response_hr.md"
            )
    ) as f:
        expected_hr_output = f.read()
    return expected_hr_output


@pytest.fixture(scope="module")
def object_provision_success():
    """Retrieve the json response for object provision."""
    return util_load_json(
        os.path.join(TEST_DATA_DIRECTORY, "object_provision_success.json")
    )


@pytest.fixture(scope="module")
def object_provision_success_hr():
    """Retrieve the human-readable for object provision."""
    with open(os.path.join(TEST_DATA_DIRECTORY, "object_provision_success.md")) as f:
        expected_hr_output = f.read()
    return expected_hr_output


@pytest.fixture(scope="module")
def service_binding_reference_success():
    return util_load_json(
        os.path.join(TEST_DATA_DIRECTORY, "create_virtual_service_success_response.json"))


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
    requests_mock.get(re.compile("/health"),
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


def test_traffic_analysis_success(mock_client, monkeypatch, traffic_analysis_create_success):
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

    monkeypatch.setattr(illumio.pce.PolicyComputeEngine, "get_traffic_flows_async",
                        lambda *a, **k: [TrafficFlow.from_json(flow) for flow in traffic_analysis_create_success])

    resp = traffic_analysis_command(mock_client, args)

    assert resp.raw_response == traffic_analysis_create_success


def test_traffic_analysis_human_readable(traffic_analysis_create_success, traffic_analysis_create_success_hr):
    """
    Test case scenario for successful execution of traffic-analysis-command function.

    Given:
        - command arguments for traffic_analysis
    When:
        - Calling `traffic_analysis_Command` function
    Then:
        - Returns a valid human-readable
    """
    resp = prepare_traffic_analysis_output(traffic_analysis_create_success)
    assert resp == traffic_analysis_create_success_hr


def test_virtual_service_create_command_for_success(mock_client, virtual_service_create_success,
                                                    monkeypatch):
    """Test case scenario for execution of virtual-service-create-command when valid and all arguments are provided.

    Given:
        - virtual_service_create_command function and mock_client to call the function
    When:
        - Valid name, port, and protocol are provided in the command argument
    Then:
        - Returns a valid raw_response
    """
    monkeypatch.setattr(illumio.pce.PolicyComputeEngine._PCEObjectAPI, "create",
                        lambda *a: VirtualService.from_json(virtual_service_create_success))
    resp = virtual_service_create_command(
        mock_client, {"name": "test_create_virtual_service", "port": 3000, "protocol": "tcp"})
    assert resp.raw_response == virtual_service_create_success


def test_virtual_service_create_command_for_human_readable(virtual_service_create_success, virtual_service_success_hr):
    """Test case scenario for execution of virtual-service-create-command when valid and all arguments are provided.

    Given:
        - virtual_service_create_command function and mock_client to call the function
    When:
        - Valid name, port, and protocol are provided in the command argument
    Then:
        - Returns a valid human-readable
    """
    resp = prepare_virtual_service_output(virtual_service_create_success)
    assert resp == virtual_service_success_hr


def test_virtual_service_create_command_for_success_with_protocol_as_udp(mock_client,
                                                                         virtual_service_create_success_udp,
                                                                         monkeypatch):
    """Test case scenario for execution of virtual-service-create-command with protocol as udp.

    Given:
        - virtual_service_create_command function and mock_client to call the function.
    When:
        - Valid name, port, and protocol are provided in the command argument.
    Then:
        - Return a valid raw_response
    """
    monkeypatch.setattr(illumio.pce.PolicyComputeEngine._PCEObjectAPI, "create",
                        lambda *a: VirtualService.from_json(virtual_service_create_success_udp))
    resp = virtual_service_create_command(mock_client, {"name": "test_create_virtual_service", "port": "3000"})

    assert resp.raw_response == virtual_service_create_success_udp


def test_virtual_service_create_command_for_human_readable_with_protocol_as_udp(virtual_service_create_success_udp,
                                                                                virtual_service_success_udp_hr):
    """Test case scenario for execution of virtual-service-create-command with protocol as udp.

    Given:
        - virtual_service_create_command function and mock_client to call the function
    When:
        - Valid name, port, and protocol are provided in the command argument
    Then:
        - Returns a valid human-readable
    """
    resp = prepare_virtual_service_output(virtual_service_create_success_udp)
    assert resp == virtual_service_success_udp_hr


def test_virtual_service_create_command_for_existing_virtual_service(requests_mock, mock_client, monkeypatch):
    """Test case scenario for virtual-service-create-command with existing virtual service.

    Given:
        - virtual_service_create_command function and mock_client to call the function
    When:
        - Virtual service already exists
    Then:
        - Should raise exception with proper error message
    """
    requests_mock.post(
        re.compile("/sec_policy/draft/virtual_services"), status_code=406,
        json=[{"token": "name_must_be_unique", "message": "Name must be unique"}]
    )
    with pytest.raises(Exception) as error:
        virtual_service_create_command(mock_client, {"name": "test_virtual_service", "port": 3000, "protocol": "tcp"})
    assert str(error.value) == "406 Client Error: None for url: {}".format(
        "https://127.0.0.1:8443/api/v2/orgs/1/sec_policy/draft/virtual_services")


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


def test_service_binding_create_command_for_success(mock_client, service_binding_success, monkeypatch,
                                                    service_binding_reference_success):
    """Test case scenario for successful execution of service-binding-create.

    Given:
        - create_service_binding_command function and mock_client to call the function
    When:
        - Valid virtual service href and valid list of workloads href are provided in the command argument
    Then:
        - Returns a valid raw_response
    """

    monkeypatch.setattr(
        illumio.pce.PolicyComputeEngine._PCEObjectAPI,
        "create",
        lambda *a: ServiceBinding.from_json(service_binding_success),
    )

    monkeypatch.setattr(illumio.pce.PolicyComputeEngine._PCEObjectAPI, "get_by_reference",
                        lambda *a: PolicyVersion.from_json(service_binding_reference_success))

    args = {"workloads": WORKLOAD_EXP_URL, "virtual_service": VIRTUAL_SERVICE_EXP_URL}
    resp = service_binding_create_command(mock_client, args)
    assert resp.raw_response == service_binding_success


def test_service_binding_create_command_for_human_readable(service_binding_success_hr):
    """Test case scenario for successful execution of service-binding-create-command.

    Given:
        - create_service_binding_command function and mock_client to call the function
    When:
        - Valid virtual service href and valid list of workloads href are provided in the command argument
    Then:
        - Returns a valid human-readable
    """
    create_service_binding_expected_resp_output = util_load_json(
        os.path.join(
            TEST_DATA_DIRECTORY, "create_service_binding_success_response_output.json"
        )
    )

    response = prepare_service_binding_output(
        create_service_binding_expected_resp_output
    )
    assert response == service_binding_success_hr


@pytest.mark.parametrize(
    "args",
    [
        ({"workloads": "abc", "virtual_service": VIRTUAL_SERVICE_EXP_URL}),
        ({"workloads": WORKLOAD_EXP_URL, "virtual_service": "abc"}),
    ],
)
def test_service_binding_create_when_invalid_arguments_provided(
        args, mock_client, requests_mock
):
    """Test case scenario when arguments provided to service-binding-create are invalid.

    Given:
        - command arguments for service-binding command
    When:
        - Calling `service_binding_create_command` function
    Then:
        - Returns a valid error message
    """
    requests_mock.post(
        re.compile("/service_bindings"),
        status_code=406,
        json=[{"token": "invalid_uri", "message": "Invalid URI: {abc}"}],
    )

    with pytest.raises(Exception) as err:
        service_binding_create_command(mock_client, args)

        assert (
                str(err.value) == "406 Client Error: None for url: https://127.0.0.1:8443/api/v2/orgs/1/service_bindings"
        )


@pytest.mark.parametrize(
    "err_msg, args",
    [
        (
                MISSING_REQUIRED_PARAM_EXCEPTION_MESSAGE.format("workloads"),
                {"workloads": "", "virtual_service": VIRTUAL_SERVICE_EXP_URL},
        ),
        (
                MISSING_REQUIRED_PARAM_EXCEPTION_MESSAGE.format("virtual_service"),
                {"workloads": WORKLOAD_EXP_URL, "virtual_service": ""},
        ),
    ],
)
def test_create_service_binding_when_blank_arguments_provided(
        err_msg, args, mock_client
):
    """Test case scenario when arguments provided to service-binding-create are blank.

    Given:
        - command arguments for service-binding-create command
    When:
        - Calling `service_binding_create_command` function
    Then:
        - Returns a valid error message
    """
    with pytest.raises(Exception) as err:
        service_binding_create_command(mock_client, args)

        assert str(err.value) == err_msg


def test_object_provision_command_when_invalid_arguments_provided(mock_client):
    """
    Test case scenario for execution of object-provision-command when invalid arguments are provided.

    Given:
        - object_provision_command function and mock_client to call the function
    When:
        - Invalid arguments (Empty values) provided in the arguments
    Then:
        - Should raise ValueError with proper error message
    """
    from IllumioCore import object_provision_command

    args = {"security_policy_objects": ""}
    err_msg = (
        "security_policy_objects is a required parameter. Please provide correct value."
    )

    with pytest.raises(ValueError) as err:
        object_provision_command(mock_client, args)

    assert str(err.value) == err_msg


def test_object_provision_command_when_valid_arguments_provided(
        mock_client, object_provision_success, monkeypatch
):
    """
    Test case scenario for execution of object-provision-command when valid arguments are provided.

    Given:
        - object_provision_command function and mock_client to call the function
    When:
        - Valid href is provided in the command argument
    Then:
        - Should return proper raw_response
    """
    monkeypatch.setattr(
        illumio.pce.PolicyComputeEngine,
        "provision_policy_changes",
        lambda *a, **k: PolicyVersion.from_json(object_provision_success),
    )
    mock_args = {"security_policy_objects": "/orgs/1/sec_policy/draft/rule_sets/1605"}
    response = object_provision_command(mock_client, mock_args)

    assert response.raw_response == object_provision_success


def test_object_provision_command_when_valid_arguments_provided_human_readable(
        mock_client, object_provision_success, object_provision_success_hr
):
    """
    Test case scenario for execution of object-provision-command when valid arguments are provided.

    Given:
        - object_provision_command function and mock_client to call the function
    When:
        - Valid href is provided in the command argument
    Then:
        - Returns a valid human-readable
    """
    resp = prepare_object_provision_output(object_provision_success)
    assert resp == object_provision_success_hr
