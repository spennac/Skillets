from panos.firewall import Firewall
from panos.base import PanDevice


class PanosApiClient:
    def __init__(self, host: str, username: str, password: str):
        self.firewall = Firewall(host, username, password)

    def generate_api_key(self) -> str:
        """Genera una API key usando el método oficial del SDK"""
        try:
            self.firewall.refresh_system_info()
            return self.firewall.api_key
        except Exception as e:
            raise RuntimeError(f"PAN-OS API Error: {str(e)}")

    @staticmethod
    def validate_connection(host: str, username: str, password: str) -> bool:
        """Valida credenciales antes de operar"""
        try:
            fw = Firewall(host, username, password)
            fw.refresh_system_info()
            return True
        except:
            return False
