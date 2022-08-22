import demistomock as demisto
import urllib3
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
from illumio import PolicyComputeEngine

urllib3.disable_warnings()

''' CONSTANTS '''

MIN_PORT = 1
MAX_PORT = 65535

'''EXCEPTION CLASS'''


class InvalidPortException(Exception):
    """Exception class for Invalid port."""

    def __init__(self, port):
        self.message = "{} is an invalid value for port. Value must be in 1 to 65535.".format(port)
        super().__init__(self.message)


''' COMMAND FUNCTIONS '''


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
        return 'ok'
    raise ValueError("Failed to establish connection with provided credentials.")


def main():
    """Parse params and runs command functions."""

    try:
        command = demisto.command()
        demisto.debug(f"Command being called is {command}.")

        params = demisto.params()
        api_user = params.get('api_user')
        api_key = params.get('api_key')

        port = arg_to_number(params.get('port'))
        if port < MIN_PORT or port > MAX_PORT:  # type: ignore
            raise InvalidPortException(port)

        org_id = arg_to_number(params.get('org_id'), required=True)
        if org_id <= 0:  # type: ignore
            raise ValueError(
                "{} is an invalid value. Organization ID must be a non-zero and positive numeric value.".format(org_id))

        base_url = params.get('url')
        proxy = handle_proxy()

        client = PolicyComputeEngine(url=base_url, port=port, org_id=org_id)
        client.set_proxies(http_proxy=proxy.get("http", None), https_proxy=proxy.get('https', None))
        client.set_credentials(api_user, api_key)

        if command == 'test-module':
            result = test_module(client)
        else:
            raise NotImplementedError(f'Command {command} is not implemented')
        return_results(result)
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
