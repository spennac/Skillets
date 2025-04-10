import os
import requests
import urllib3
import xml.etree.ElementTree as ET

# Desactivar advertencias de certificado SSL (sólo para entornos de prueba)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuración del firewall
fw_ip = os.environ.get('TARGET_IP', 'default')
username = os.environ.get('TARGET_USERNAME', 'default')
password = os.environ.get('TARGET_PASSWORD', 'default')

# URL para generar la API key
url = f'https://{fw_ip}/api/?type=keygen&user={username}&password={password}'

try:
    # Realizar la solicitud HTTPS (ignorando verificación SSL para pruebas)
    response = requests.get(url, verify=False)

    # Verificar si la solicitud fue exitosa
    if response.status_code == 200:
        # Parsear la respuesta XML
        root = ET.fromstring(response.text)

        # Extraer la API key
        if root.attrib['status'] == 'success':
            api_key = root.find('.//key').text
            print(f"API Key generada con éxito: {api_key}")
        else:
            print("Error al generar la API key:", root.attrib['status'])
    else:
        print(
            f"Error en la solicitud. Código de estado: {response.status_code}")

except requests.exceptions.RequestException as e:
    print(f"Error de conexión: {e}")
except ET.ParseError as e:
    print(f"Error al parsear la respuesta XML: {e}")
