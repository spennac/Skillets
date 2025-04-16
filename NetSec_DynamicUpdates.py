import click
from skilletlib import Panos
from skilletlib.exceptions import LoginException
from skilletlib.exceptions import SkilletLoaderException


@click.command()
@click.option("-i", "--TARGET_IP", help="IP address of the device (localhost)", type=str, default="localhost")
@click.option("-r", "--target_port", help="Port to communicate to NGFW (443)", type=int, default=443)
@click.option("-u", "--TARGET_USERNAME", help="Firewall Username (admin)", type=str, default="admin")
@click.option("-p", "--TARGET_PASSWORD", help="Firewall Password (admin)", type=str, default="admin")
@click.option("-t", "--CONTENT_TYPE", help="Type of dynamic update to update", type=str, default="content")
def cli(target_ip, target_port, target_username, target_password, content_type):
    """
    Load a baseline configuration. Takes a content_type argument that specifies what type of content to update.
    Valid options are 'content', 'anti-virus', 'global-protect-client', 'wildfire'
    for more information, see here: https://docs.paloaltonetworks.com/pan-os/8-0/pan-os-panorama-api/pan-os-xml-api-use-cases/automatically-check-for-and-install-content-updates-api#
    """

    try:

        device = Panos(api_username=target_username,
                       api_password=target_password,
                       hostname=target_ip,
                       api_port=target_port
                       )

        if not device.update_dynamic_content(content_type):
            exit(1)

        exit(0)

    except LoginException as lxe:
        print(lxe)
        exit(1)
    except SkilletLoaderException as pe:
        print(pe)
        exit(1)

    # failsafe
    exit(1)


if __name__ == '__main__':
    cli()
