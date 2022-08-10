import demistomock as demisto
import urllib3
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
from illumio import PolicyComputeEngine

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
ERRORS = {
    'INVALID_ORG_ID': "{} is an invalid value. Organization ID must be a non-zero and positive numeric value.",
    'NO_RECORDS': 'No Record Found.',
    'MISSING_REQUIRED_PARAM': "{} is a required parameter. Please provide correct value.",
    'INVALID_PORT_NUMBER': '{} is an invalid value for port. Value must be in 1 to 65535.',
    'INVALID_SINGLE_SELECT_PARAM': '{} is an invalid value for {}. Possible values are: {}.',
    'INVALID_MULTI_SELECT_PARAM': "Invalid value for {}. Possible comma separated values are {}."
}

''' CLIENT CLASS '''


class IllumioClient:
    """IllumioClient class to interact with the service SDK"""

    def __init__(self, base_url: str, api_user: str, api_key: str, proxy: dict, org_id: int) -> None:
        port = base_url.split(':')[-1]
        self.pce = PolicyComputeEngine(url=base_url, port=port, org_id=org_id)
        self.pce.set_proxies(http_proxy=proxy.get("http"), https_proxy=proxy.get('https'))
        self.pce.set_credentials(api_user, api_key)


''' COMMAND FUNCTIONS '''


def test_module(client: IllumioClient) -> str:
    """Tests API connectivity and authentication.

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises:
     exceptions if something goes wrong.

    :type client: ``IllumioClient``
    :param client: IllumioClient to be used.

    :rtype: ``str``
    :return: 'ok' if test passed, anything else will fail the test.
    """

    params = {
        "max_results": 1
    }
    client.pce.workloads.get(params=params)
    return 'ok'


def main():
    """main function, parses params and runs command functions"""

    params = demisto.params()
    api_user = params.get('api_user')
    api_key = params.get('api_key')
    org_id = arg_to_number(params.get('org_id'))
    if org_id is None or org_id <= 0:
        raise ValueError(ERRORS['INVALID_ORG_ID'].format(org_id))
    base_url = params.get('url')
    proxy = handle_proxy()

    command = demisto.command()
    demisto.debug(f"Command being called is {command}.")
    try:

        client = IllumioClient(
            base_url=base_url,
            proxy=proxy,
            api_user=api_user,
            api_key=api_key,
            org_id=org_id
        )
        if command == 'test-module':
            result = test_module(client)
        else:
            raise NotImplementedError(f'Command {command} is not implemented')
        return_results(result)  # Returns either str, CommandResults and a list of CommandResults
    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
