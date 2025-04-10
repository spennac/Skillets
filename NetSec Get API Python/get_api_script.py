import os
import sys
import requests
import xml.etree.ElementTree as ET
from requests.exceptions import RequestException

# Configuración desde variables de entorno
FW_IP = os.getenv('TARGET_IP', '').strip()
USERNAME = os.getenv('TARGET_USERNAME', '').strip()
PASSWORD = os.getenv('TARGET_PASSWORD', '').strip()

# Validación básica de inputs
if not all([FW_IP, USERNAME, PASSWORD]):
    sys.stderr.write(
        "Error: Faltan variables de entorno (TARGET_IP/USERNAME/PASSWORD)\n")
    sys.exit(1)


def generate_api_key(FW_IP: str, USERNAME: str, PASSWORD: str) -> str:
    """Genera API Key y maneja errores estructurados"""
    url = f"https://{FW_IP}/api/?type=keygen&user={USERNAME}&password={PASSWORD}"

    try:
        response = requests.get(
            url,
            verify=True,  # En producción, usa certificados válidos
            timeout=10
        )
        response.raise_for_status()  # Lanza excepción para códigos 4xx/5xx

        root = ET.fromstring(response.text)
        if root.attrib.get('status') != 'success':
            raise ValueError(f"API respondió con error: {root.attrib}")

        api_key = root.find('.//key').text
        if not api_key:
            raise ValueError("No se encontró API Key en la respuesta")

        return api_key

    except RequestException as e:
        raise ConnectionError(f"Error de conexión con {FW_IP}: {str(e)}")
    except ET.ParseError:
        raise ValueError("Respuesta XML malformada del firewall")


if __name__ == "__main__":
    try:
        api_key = generate_api_key(FW_IP, USERNAME, PASSWORD)
        print(f"API_KEY={api_key}")
        sys.exit(0)
    except Exception as e:
        sys.stderr.write(f"ERROR: {str(e)}\n")
        sys.exit(1)
