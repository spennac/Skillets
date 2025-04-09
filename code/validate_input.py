def validate(input_data):
    if not input_data.get("mgmt_ip"):
        return False, "La IP de gestión es requerida"
    if "/" not in input_data["mgmt_ip"]:
        return False, "La IP debe incluir máscara (ej: 192.168.1.1/24)"
    return True, "Input válido"
