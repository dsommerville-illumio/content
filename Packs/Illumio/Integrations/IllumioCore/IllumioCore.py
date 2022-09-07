"""Implementation file for IllumioCore Integration."""
from enum import Enum

import urllib3
from datetime import datetime
from illumio import PolicyComputeEngine, IllumioEncoder, convert_draft_href_to_active, IllumioException
from illumio.explorer import TrafficQuery
from illumio.policyobjects import VirtualService, ServicePort, ServiceBinding, Reference
from illumio.util import convert_protocol
import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

urllib3.disable_warnings()

""" CONSTANTS """

MIN_PORT = 1
MAX_PORT = 65535
HR_DATE_FORMAT = "%d %b %Y, %I:%M %p"
VALID_PROTOCOLS = ["tcp", "udp"]
VALID_POLICY_DECISIONS = ["potentially_blocked", "blocked", "unknown", "allowed"]
SUPPORTED_ENFORCEMENT_MODES = ["visibility_only", "full", "idle", "selective"]
SUPPORTED_VISIBILITY_LEVEL = ["flow_full_detail", "flow_summary", "flow_drops", "flow_off", "enhanced_data_collection"]


class Protocol(Enum):
    """Enum for protocols."""
    TCP = 6
    UDP = 17


"""EXCEPTION CLASS"""


class InvalidValueError(Exception):
    """Custom exception class for invalid values."""

    def __init__(self, arg_name="", arg_value="", arg_list=[], message=""):
        if not message:
            message = "{} is an invalid value for {}. Possible values are: {}".format(
                arg_value, arg_name, arg_list
            )
        super().__init__(message)


""" HELPER FUNCTIONS """


def validate_required_parameters(**kwargs) -> None:
    """Raise an error for a required parameter.

    Enter your required parameters as keyword arguments to check
    whether they hold a value or not.

    Args:
        **kwargs: keyword arguments to check the required values for.

    Returns:
        Error if the value of the parameter is "", [], (), {}, None.
    """
    for key, value in kwargs.items():
        if not value:
            raise ValueError("{} is a required parameter. Please provide correct value.".format(key))


def trim_spaces_from_args(args: Dict) -> Dict:
    """Trim spaces from values of the args dict.

    Args:
        args: Dict to trim spaces from.

    Returns: Arguments after trim spaces.
    """
    for key, val in args.items():
        if isinstance(val, str):
            args[key] = val.strip()

    return args


def generate_change_description_for_object_provision(hrefs: List[str]) -> str:
    """
    Generate a unique message for object provision command's change description argument.

    Args:
        hrefs: List of HREFs to be provisioned.

    Returns:
        str: A string with the current time in UTC.
    """
    return "XSOAR - {}\nProvisioning following objects:\n{}".format(
        datetime.now().astimezone(timezone.utc).isoformat()[:-6], ', '.join(hrefs))


def validate_traffic_analysis_arguments(port: Optional[int], policy_decisions: list, protocol: str) -> None:
    """Validate arguments for traffic-analysis command.

    Args:
        port: Port number.
        policy_decisions: Policy decision to include in the search result.
        protocol: Communication protocol.
    """
    if port < MIN_PORT or port > MAX_PORT:  # type: ignore
        raise InvalidValueError(message="{} invalid value for port. Value must be in 1 to 65535.".format(port))

    for decision in policy_decisions:
        if decision not in VALID_POLICY_DECISIONS:
            raise InvalidValueError("policy_decisions", decision, VALID_POLICY_DECISIONS)

    if protocol not in VALID_PROTOCOLS:
        raise InvalidValueError("protocol", protocol, VALID_PROTOCOLS)


def validate_virtual_service_arguments(port: int | None, protocol: str) -> None:
    """Validate arguments for virtual-service-create command.

    Args:
        port: Port number.
        protocol: Protocol name.
    """
    if port != -1 and (port > MAX_PORT or port < MIN_PORT or port == 0):  # type: ignore
        raise InvalidValueError(
            message="{} is an invalid value for port. Value must be in 1 to 65535 or -1.".format(port))

    if protocol not in VALID_PROTOCOLS:
        raise InvalidValueError("protocol", protocol, VALID_PROTOCOLS)


def prepare_traffic_analysis_output(response: list) -> str:
    """Prepare Human Readable output for traffic-analysis-command.

    Args:
        response: Response from the SDK.

    Returns:
        markdown string to be displayed in the war room.
    """
    hr_output = []

    for traffic in response:
        hr_output.append({
            "Source IP": traffic.get("src", {}).get("ip"),
            "Destination IP": traffic.get("dst", {}).get("ip"),
            "Destination Workload Hostname": traffic.get("dst", {}).get("workload", {}).get("hostname"),
            "Service Port": traffic.get("service", {}).get("port"),
            "Service Protocol": Protocol(traffic.get("service").get("proto")).name,
            "Policy Decision": traffic.get("policy_decision"),
            "State": traffic.get("state"),
            "Flow Direction": traffic.get("flow_direction"),
            "First Detected": arg_to_datetime(
                traffic["timestamp_range"]["first_detected"]).strftime(HR_DATE_FORMAT),  # type: ignore
            "Last Detected": arg_to_datetime(
                traffic["timestamp_range"]["last_detected"]).strftime(HR_DATE_FORMAT)  # type: ignore

        })

    headers = list(hr_output[0].keys()) if hr_output else []

    return tableToMarkdown("Traffic Analysis:", hr_output, headers=headers, removeNull=True)


def prepare_virtual_service_output(response: dict) -> str:
    """Prepare human-readable output for virtual-service-create command.

    Args:
        response: result returned after creating Virtual Service.

    Returns:
        markdown string to be displayed in the war room.
    """
    hr_output = []
    for service_port in response.get("service_ports", []):
        hr_output.append({
            "Virtual Service HREF": response.get("href"),
            "Created At": arg_to_datetime(response["created_at"]).strftime(HR_DATE_FORMAT),  # type: ignore
            "Updated At": arg_to_datetime(response["updated_at"]).strftime(HR_DATE_FORMAT),  # type: ignore
            "Name": response.get("name"),
            "Description": response.get("description"),
            "Service Port": service_port.get("port") if "port" in service_port else "all ports have been selected",
            "Service Protocol": Protocol(service_port.get("proto")).name,
        })

    headers = list(hr_output[0].keys()) if hr_output else []
    title = f'Virtual Service:\n#### Successfully created virtual service: {response.get("href")}\n'
    return tableToMarkdown(title, hr_output, headers=headers, removeNull=True)


def prepare_service_binding_output(response: dict) -> str:
    """Prepare human-readable output for service-binding-create command.

    Args:
        response: result returned after create service binding.

    Returns:
        markdown string to be displayed in the war room.
    """
    hr_outputs = []

    if response.get("errors") and not response.get("service_bindings"):
        title = "Service Binding:\n#### Workloads are already bounded to the virtual service."
    else:
        for result in response.get("service_bindings", []):
            hr_outputs.append({"Service Binding HREF": result["href"], "Status": "created"})
        title = "Service Binding:\n#### Workloads have been bounded to the virtual service successfully."

    headers = list(hr_outputs[0].keys()) if hr_outputs else []
    return tableToMarkdown(title, hr_outputs, headers=headers, removeNull=True)


def prepare_object_provision_output(response: Dict[str, Any]) -> str:
    """
    Prepare human-readable output for objects-provision command.

    Args:
        response: Response received from the SDK.

    Returns:
        str: Human-readable markdown string.
    """
    created_at = response.get('created_at')
    if created_at:
        created_at = arg_to_datetime(created_at).strftime(HR_DATE_FORMAT)  # type: ignore

    hr_output = {
        "Provision Object URI": response.get("href"),
        "Commit Message": response.get("commit_message"),
        "Created At": created_at
    }

    return tableToMarkdown("Provision Objects:",
                           hr_output,
                           headers=["Provision Object URI", "Commit Message", "Created At"],
                           metadata="Provision is completed for {}".format(response.get('href')),
                           removeNull=True)


""" COMMAND FUNCTIONS """


def test_module(client: PolicyComputeEngine) -> str:
    """Tests API connectivity and authentication.

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.

    Args:
        client: PolicyComputeEngine to be used.

    Returns: 'ok' if test passed, anything else will fail the test.
    """
    response = client.check_connection()
    if response:
        return "ok"
    raise ValueError("Failed to establish connection with provided credentials.")


def traffic_analysis_command(client: PolicyComputeEngine, args: Dict[str, Any]) -> CommandResults:
    """Retrieve the traffic for a particular port and protocol.

    Args:
        client: PolicyComputeEngine to use.
        args: arguments obtained from demisto.args()

    Returns: CommandResult object
    """
    port = arg_to_number(args.get("port"))
    protocol = args.get("protocol", "tcp").lower()
    start_time = arg_to_datetime(args.get("start_time", "1 week ago")).isoformat()  # type: ignore
    end_time = arg_to_datetime(args.get("end_time", "now")).isoformat()  # type: ignore
    policy_decisions = argToList(args.get("policy_decisions", "potentially_blocked,unknown"))
    validate_required_parameters(port=port)
    validate_traffic_analysis_arguments(port, policy_decisions, protocol)  # type: ignore
    query_name = "XSOAR - Traffic analysis for port {}: {}".format(port, datetime.now().isoformat())
    proto = convert_protocol(protocol)
    service = ServicePort(port, proto=proto)  # type: ignore

    traffic_query = TrafficQuery.build(
        start_date=start_time, end_date=end_time, policy_decisions=policy_decisions, include_services=[service]
    )

    response = client.get_traffic_flows_async(query_name=query_name, traffic_query=traffic_query)
    json_response = []
    for resp in response:
        resp = resp.to_json()
        json_response.append(resp)

    readable_output = prepare_traffic_analysis_output(json_response)
    return CommandResults(
        outputs_prefix="Illumio.TrafficFlows",
        outputs_key_field="href",
        outputs=remove_empty_elements(json_response),  # type: ignore
        readable_output=readable_output,
        raw_response=json_response,
    )


def virtual_service_create_command(client: PolicyComputeEngine, args: Dict[str, any]) -> CommandResults:  # type: ignore
    """Create a virtual service.

    Args:
        client: PolicyComputeEngine to use.
        args: arguments obtained from demisto.args()

    Returns: CommandResult object
    """
    port = args.get("port")
    protocol = args.get("protocol", "tcp").lower()
    name = args.get("name")

    validate_required_parameters(name=name, port=port)
    port = arg_to_number(port, arg_name="port")
    validate_virtual_service_arguments(port, protocol)
    proto = convert_protocol(protocol)

    service = VirtualService(name=name, service_ports=[ServicePort(port=port, proto=proto)])  # type: ignore
    virtual_service = client.virtual_services.create(service)  # type: ignore
    virtual_service_json = virtual_service.to_json()
    hr_output = prepare_virtual_service_output(virtual_service_json)
    return CommandResults(
        outputs_prefix="Illumio.VirtualService",
        readable_output=hr_output,
        outputs_key_field="href",
        raw_response=virtual_service_json,
        outputs=remove_empty_elements(virtual_service_json),
    )


def service_binding_create_command(client: PolicyComputeEngine, args: dict[str, Any]) -> CommandResults:
    """Create a service binding.

    Args:
        client: PolicyComputeEngine to use.
        args: arguments obtained from demisto.args()

    Returns:
        CommandResult object
    """
    workloads = args.get("workloads")
    virtual_service = args.get("virtual_service")

    validate_required_parameters(workloads=workloads, virtual_service=virtual_service)
    workloads = argToList(workloads)
    virtual_service = convert_draft_href_to_active(args.get("virtual_service"))
    try:
        client.virtual_services.get_by_reference(virtual_service)
    except IllumioException as e:
        raise InvalidValueError(
            message="no active record for virtual service with HREF {}".format(virtual_service)) from e

    service_bindings = [
        ServiceBinding(virtual_service=Reference(href=virtual_service), workload=Reference(href=href))  # type: ignore
        for href in workloads
    ]

    response = client.service_bindings.create(service_bindings)  # type: ignore
    results = json.loads(json.dumps(response, cls=IllumioEncoder))
    readable_output = prepare_service_binding_output(results)

    return CommandResults(
        outputs_prefix="Illumio.ServiceBinding",
        readable_output=readable_output,
        outputs_key_field="href",
        outputs=remove_empty_elements(results),
        raw_response=results,
    )


def object_provision_command(client: PolicyComputeEngine, args: Dict[str, Any]) -> CommandResults:
    """
    Command function for illumio-objects-provision command.

    Args:
        client: Client object to be used.
        args: Arguments passed with the command.

    Returns:
        Standard command results.
    """
    security_policy_objects = args.get("security_policy_objects", "")
    validate_required_parameters(security_policy_objects=security_policy_objects)
    security_policy_objects = argToList(security_policy_objects)
    change_description = generate_change_description_for_object_provision(hrefs=security_policy_objects)

    response_object = client.provision_policy_changes(
        change_description=change_description, hrefs=security_policy_objects)
    response_dict = response_object.to_json()

    hr_output = prepare_object_provision_output(response_dict)

    # Converting draft HREFs to active
    provisioned_hrefs = [convert_draft_href_to_active(href) for href in security_policy_objects]

    response_dict["provisioned_hrefs"] = provisioned_hrefs

    return CommandResults(outputs_prefix="Illumio.PolicyState", outputs_key_field="href",
                          outputs=remove_empty_elements(response_dict), readable_output=hr_output,
                          raw_response=response_dict)


def main():
    """Parse params and runs command functions."""
    try:
        command = demisto.command()
        demisto.debug(f"Command being called is {command}.")

        params = demisto.params()
        api_user = params.get("api_user")
        api_key = params.get("api_key")

        port = arg_to_number(params.get("port"), required=True, arg_name="port")
        if port < MIN_PORT or port > MAX_PORT:  # type: ignore
            raise InvalidValueError(
                message="{} is an invalid value for port. Value must be in 1 to 65535.".format(port))

        org_id = arg_to_number(params.get("org_id"), required=True, arg_name="org_id")
        if org_id <= 0:  # type: ignore
            raise ValueError(
                "{} is an invalid value. Organization ID must be a non-zero and positive numeric value.".format(org_id)
            )

        base_url = params.get("url").strip()
        if not base_url:
            raise ValueError("Server URL is required.")

        proxy = handle_proxy()

        client = PolicyComputeEngine(url=base_url, port=port, org_id=org_id)
        client.set_proxies(http_proxy=proxy.get("http", None), https_proxy=proxy.get("https", None))
        client.set_credentials(api_user, api_key)

        if command == "test-module":
            return_results(test_module(client))
        else:
            illumio_commands = {
                "illumio-traffic-analysis": traffic_analysis_command,
                "illumio-virtual-service-create": virtual_service_create_command,
                "illumio-service-binding-create": service_binding_create_command,
                "illumio-object-provision": object_provision_command
            }
            if command in illumio_commands:
                args = demisto.args()
                remove_nulls_from_dictionary(trim_spaces_from_args(args))
                return_results(illumio_commands[command](client, args))
            else:
                raise NotImplementedError(f"Command {command} is not implemented")
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
