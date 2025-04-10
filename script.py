#!/usr/bin/env python3
"""
Configuración inicial de PAN-OS - Políticas de seguridad basadas en App-ID
"""

from pandevice import firewall
from pandevice import policies
from pandevice.errors import PanDeviceError
import os
import sys


def configurar_politicas_seguridad(fw):
    """Configura políticas de seguridad basadas en App-ID"""

    print("\n=== Configurando Políticas de Seguridad ===")

    # Obtener rulebase existente o crear nueva
    rulebase = fw.find(policies.Rulebase) or policies.Rulebase()
    fw.add(rulebase)

    # 1. Política de denegación por defecto (con logging)
    regla_deny = policies.SecurityRule(
        name="Deny-All",
        description="Bloquear todo el tráfico no permitido explícitamente",
        fromzone=["any"],
        tozone=["any"],
        source=["any"],
        destination=["any"],
        application=["any"],
        service=["application-default"],
        action="deny",
        log_setting="log-both"
    )

    # 2. Política de descifrado SSL
    regla_decrypt = policies.SecurityRule(
        name="Decrypt-Outbound",
        description="Descifrar tráfico saliente para inspección",
        fromzone=["trust"],
        tozone=["untrust"],
        source=["any"],
        destination=["any"],
        application=["web-browsing", "ssl"],
        action="decrypt",
        log_setting="log-both"
    )

    # 3. Política para tráfico web seguro
    regla_web = policies.SecurityRule(
        name="Allow-Web",
        description="Permitir tráfico web seguro",
        fromzone=["any"],
        tozone=["any"],
        source=["any"],
        destination=["any"],
        application=["web-browsing", "ssl"],
        action="allow",
        log_setting="log-start"
    )

    # 4. Política para DNS seguro (DoH/DoT)
    regla_dns = policies.SecurityRule(
        name="Allow-Secure-DNS",
        description="Permitir solo DNS sobre HTTPS/TLS",
        fromzone=["any"],
        tozone=["any"],
        source=["any"],
        destination=["any"],
        application=["dns-over-https", "dns-over-tls"],
        action="allow",
        log_setting="log-start"
    )

    # Lista de reglas a configurar
    reglas = [regla_deny, regla_decrypt, regla_web, regla_dns]

    # Aplicar reglas si no existen
    for regla in reglas:
        if not rulebase.find(policies.SecurityRule, regla.name):
            rulebase.add(regla)
            regla.create()
            print(f"Política '{regla.name}' configurada")
        else:
            print(f"Política '{regla.name}' ya existe - omitiendo")


def main():
    # Obtener parámetros de Panhandler
    hostname = os.getenv('TARGET_IP', '127.0.0.1')
    username = os.getenv('TARGET_USERNAME', 'admin')
    password = os.getenv('TARGET_PASSWORD', 'paloalto')

    try:
        # Conectar al firewall
        fw = firewall.Firewall(hostname, username, password)
        print(f"Conectado a {hostname} exitosamente")

        # Aplicar configuración de políticas
        configurar_politicas_seguridad(fw)

        # Commit de cambios
        fw.commit(sync=True)
        print("\nConfiguración aplicada exitosamente")
        print("::set-output name=status::success")

    except PanDeviceError as e:
        print(f"Error: {str(e)}")
        print("::set-output name=status::failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
