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


''' CLIENT CLASS '''


class IllumioClient:
    """IllumioClient class to interact with the service SDK."""

    def __init__(self, base_url: str, port: int, api_user: str, api_key: str, proxy: dict, org_id: int) -> None:
        """Construct IllumioClient class object.

        Args:
            base_url: the base url to establish connection with the illumio sdk.
            port: the port number to establish connection.
            api_user: the username to authenticate with the illumio sdk.
            api_key: the api key to authenticate with the illumio sdk.
            proxy: whether to use the demisto's proxy settings or not.
            org_id: the id of the organization to be referenced.
        """
        self.pce = PolicyComputeEngine(url=base_url, port=port, org_id=org_id)
        self.pce.set_proxies(http_proxy=proxy.get("http"), https_proxy=proxy.get('https'))
        self.pce.set_credentials(api_user, api_key)


def test_module(client: IllumioClient) -> str:
    """Tests API connectivity and authentication.

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.

    Args:
        client: IllumioClient to be used.

    Returns: 'ok' if test passed, anything else will fail the test.
    """
    response = client.pce.check_connection()
    if response:
        return 'ok'
    raise ValueError("Failed to establish connection with provided credentials.")


def main():
    """Parse params and runs command functions."""
    params = demisto.params()
    api_user = params.get('api_user')
    api_key = params.get('api_key')

    port = arg_to_number(params.get('port'))
    if port < MIN_PORT or port > MAX_PORT:  # type: ignore
        raise InvalidPortException(port)

    org_id = arg_to_number(params.get('org_id'), required=True)
    if org_id <= 0:  # type: ignore
        return_error(
            message="{} is an invalid value. Organization ID must be a non-zero and positive numeric value.".format(
                port))

    base_url = params.get('url')
    proxy = handle_proxy()

    command = demisto.command()
    demisto.debug(f"Command being called is {command}.")
    try:

        client = IllumioClient(
            base_url=base_url,
            port=port,  # type: ignore
            proxy=proxy,
            api_user=api_user,
            api_key=api_key,
            org_id=org_id  # type: ignore
        )
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
