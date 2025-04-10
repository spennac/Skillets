#!/usr/bin/env python3
import os
import sys
from panos_api_client import PanosApiClient


def main():
    # Carga variables desde Panhandler
    target_ip = os.getenv('target_ip')
    username = os.getenv('username')
    password = os.getenv('password')

    # Validación básica
    if not all([target_ip, username, password]):
        print("ERROR: Missing required variables", file=sys.stderr)
        sys.exit(1)

    try:
        # Usa el cliente oficial
        client = PanosApiClient(target_ip, username, password)

        if not client.validate_connection():
            raise RuntimeError("Invalid credentials or unreachable firewall")

        api_key = client.generate_api_key()
        print(f"api_key={api_key}")  # Output para Panhandler

    except Exception as e:
        print(f"ERROR: {str(e)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
