import os
from panos import firewall
from panos.policies import SecurityRule


def crear_reglas_buenas_practicas(fw, from_zones, to_zones):
    """Crea reglas de seguridad con buenas prácticas"""
    print(
        f"::set-output name=status::Creando reglas de seguridad para zonas {from_zones}->{to_zones}...")

    # Lista de reglas a crear (nombre, origen, destino, servicio, acción, descripción)
    reglas = [
        ("Permitir DNS saliente", ["192.168.1.0/24"], "any", ["udp/53"], "allow",
         "Permitir resolución DNS hacia internet"),
        ("Permitir HTTP/HTTPS saliente", ["192.168.1.0/24"], "any", ["tcp/80", "tcp/443"], "allow",
         "Permitir navegación web hacia internet"),
        ("Denegar tráfico interno no autorizado", ["192.168.1.0/24"], "192.168.1.0/24", "any", "deny",
         "Bloquear tráfico lateral no autorizado entre hosts internos"),
        ("Acceso SSH a servidores", ["172.16.0.0/24"], ["10.0.0.10-10.0.0.20"], ["tcp/22"], "allow",
         "Permitir acceso SSH desde usuarios VPN a servidores"),
        ("Acceso web a DMZ", "any", ["10.0.0.0/24"], ["tcp/80", "tcp/443"], "allow",
         "Permitir acceso web a servidores en DMZ"),
        ("Denegar todo lo demás", "any", "any", "any", "deny",
         "Regla de denegación explícita final"),
    ]

    for nombre, origen, destino, servicio, accion, descripcion in reglas:
        try:
            rule = SecurityRule(
                name=nombre,
                fromzone=from_zones,
                tozone=to_zones,
                source=origen,
                destination=destino,
                service=servicio,
                action=accion,
                description=descripcion
            )
            fw.add(rule)
            rule.create()
            print(f"Regla creada: {nombre}")
        except Exception as e:
            print(f"Error al crear regla {nombre}: {e}")


def main():
    hostname = os.getenv('TARGET_IP', '127.0.0.1')
    username = os.getenv('TARGET_USERNAME', 'admin')
    password = os.getenv('TARGET_PASSWORD', 'paloalto')

    # Obtener zonas de las variables del skillet
    from_zones = os.getenv('FROM_ZONES', 'trust,untrust').split(',')
    to_zones = os.getenv('TO_ZONES', 'trust,untrust').split(',')

    try:
        # Establecer conexión con el firewall
        fw = firewall.Firewall(hostname, username, password)
        print("::set-output name=status::Conexión establecida correctamente!")

        crear_reglas_buenas_practicas(fw, from_zones, to_zones)

        print("::set-output name=status::Configuración completada con éxito!")
    except Exception as e:
        print(f"::set-output name=status::Error: {str(e)}")


if __name__ == "__main__":
    main()
