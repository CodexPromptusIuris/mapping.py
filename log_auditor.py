import os
import subprocess
import stat

def check_log_immutability():
    """
    Verifica la integridad de los logs críticos del sistema.
    Valida si están protegidos contra borrado (append-only) y permisos restrictivos.
    """
    target_logs = [
        "/var/log/auth.log",  # Intentos de acceso (Debian/Ubuntu)
        "/var/log/secure",    # Intentos de acceso (RHEL/CentOS)
        "/var/log/syslog",    # Logs generales
        "/var/log/messages"
    ]
    
    findings = []
    log_found = False

    for log_path in target_logs:
        if not os.path.exists(log_path):
            continue
        
        log_found = True
        risk_level = "BAJO"
        status = "CUMPLE"
        details = []

        # 1. Verificar Permisos (Deberían ser 640 o 600)
        file_stat = os.stat(log_path)
        permissions = oct(file_stat.st_mode)[-3:]
        
        if int(permissions) > 644:
            status = "FALLA"
            risk_level = "ALTO"
            details.append(f"Permisos inseguros: {permissions} (Se recomienda 600 o 640)")

        # 2. Verificar Atributos Extendidos (chattr +a)
        # Esto impide que el archivo sea borrado o sobrescrito, solo permite agregar líneas.
        try:
            # Ejecutamos lsattr para ver atributos
            result = subprocess.run(['lsattr', log_path], capture_output=True, text=True)
            attributes = result.stdout.split()[0]
            
            if 'a' not in attributes:
                status = "ADVERTENCIA" # No es obligatorio, pero es recomendado para ISO 27001
                risk_level = "MEDIO"
                details.append("Falta atributo 'append-only' (+a). Los logs pueden ser borrados por root.")
            else:
                details.append("Protección contra borrado (+a) ACTIVA.")
                
        except Exception as e:
            details.append(f"No se pudo verificar atributos extendidos: {str(e)}")

        findings.append({
            "recurso": log_path,
            "estado": status,
            "riesgo": risk_level,
            "detalles": "; ".join(details)
        })

    if not log_found:
        return {
            "control": "TECH_LOG_003",
            "estado": "ERROR",
            "evidencia": "No se encontraron archivos de log estándar en el sistema."
        }

    # Si hay algún fallo crítico, el control general falla
    overall_status = "FALLA" if any(f['estado'] == "FALLA" for f in findings) else "CUMPLE"
    
    return {
        "control": "TECH_LOG_003",
        "estado": overall_status,
        "evidencia": findings
    }

# Prueba rápida si ejecutas este archivo directo
if __name__ == "__main__":
    import json
    print(json.dumps(check_log_immutability(), indent=4))
