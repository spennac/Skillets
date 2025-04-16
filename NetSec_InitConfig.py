from panos.firewall import Firewall
from panos.policies import SecurityRule, Rulebase
import logging

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def conectar_firewall(hostname, username, password):
    """Establece conexión con el firewall con manejo de errores"""
    try:
        fw = Firewall(hostname, username, password)
        logger.info(f"Conexión establecida con {hostname}")
        return fw
    except Exception as e:
        logger.error(f"Error al conectar al firewall: {str(e)}")
        raise


def crear_regla_seguridad(
    fw,
    rulebase,
    nombre,
    from_zones,
    to_zones,
    source,
    destination,
    service,
    action,
    description,
    profiles=None
):
    """
    Crea una regla de seguridad con configuraciones robustas

    Args:
        fw: Objeto Firewall
        rulebase: Objeto Rulebase
        nombre (str): Nombre de la regla
        from_zones (list): Zonas de origen
        to_zones (list): Zonas de destino
        source (list): Direcciones/origen
        destination (list): Direcciones/destino
        service (list): Servicios
        action (str): allow/deny/drop
        description (str): Descripción de la regla
        log_setting (str): Configuración de logging
    """
    try:

        rule = SecurityRule(
            name=nombre,
            fromzone=from_zones,
            tozone=to_zones,
            source=source,
            destination=destination,
            service=service,
            action=action,
            description=description,
        )

        rulebase.add(rule)
        rule.create()
        logger.info(f"Regla creada exitosamente: {nombre}")
        return rule

    except Exception as e:
        logger.error(f"Error al crear regla {nombre}: {str(e)}")
        raise


def crear_reglas_buenas_practicas(fw):
    """Crea un conjunto de reglas de seguridad con buenas prácticas"""
    try:
        # Obtener el rulebase
        rulebase = Rulebase()
        fw.add(rulebase)

        # Lista de reglas a crear
        reglas_config = [
            {
                "nombre": "Deny All",
                "from_zones": ["any"],
                "to_zones": ["any"],
                "source": ["any"],
                "destination": ["any"],
                "service": ["any"],
                "action": "deny",
                "description": "Regla de denegación explícita final"
            },
            # Puedes agregar más reglas aquí según necesites
            # Ejemplo:
            # {
            #     "nombre": "Permitir DNS",
            #     "from_zones": ["trust"],
            #     "to_zones": ["untrust"],
            #     "source": ["10.0.0.0/24"],
            #     "destination": ["8.8.8.8", "8.8.4.4"],
            #     "service": ["udp/53"],
            #     "action": "allow",
            #     "description": "Permitir tráfico DNS a servidores públicos"
            # }
        ]

        for config in reglas_config:
            crear_regla_seguridad(fw, rulebase, **config)

    except Exception as e:
        logger.error(f"Error en creación de reglas: {str(e)}")
        raise


def main():
    # Configuración del firewall (¡NUNCA guardes credenciales en código!)
    hostname = 'TARGET_IP'  # Reemplaza con tu IP
    username = 'TARGET_USERNAME'     # Reemplaza con tu usuario
    password = 'TARGET_PASSWORD'    # Reemplaza con tu contraseña

    try:
        # Establecer conexión
        fw = conectar_firewall(hostname, username, password)

        # Crear reglas
        crear_reglas_buenas_practicas(fw)

        logger.info("Configuración completada con éxito!")

    except Exception as e:
        logger.error(f"Error en la ejecución principal: {str(e)}")
        return 1

    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
