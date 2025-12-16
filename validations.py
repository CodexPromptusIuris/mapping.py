import os
import subprocess
import stat
import shutil

# --- FUNCIONES DE VALIDACIÓN TÉCNICA ---

def check_log_immutability():
    """
    Valida si los logs críticos tienen el atributo 'append-only' (+a)
    y permisos restrictivos (600/640).
    Requerido para: Trazabilidad Forense (Ley 21.719 y 21.459).
    """
    target_logs = ["/var/log/auth.log", "/var/log/syslog", "/var/log/secure", "/var/log/messages"]
    findings = []
    
    # Si no estamos en Linux/Unix, devolvemos un error controlado (para pruebas en Windows)
    if os.name != 'posix':
        return {
            "control": "TECH_LOG_003",
            "estado": "SKIPPED",
            "evidencia": "Este control solo es ejecutable en sistemas Linux/Unix."
        }

    log_found = False
    for log_path in target_logs:
        if not os.path.exists(log_path):
            continue
        
        log_found = True
        status = "CUMPLE"
        details = []

        # 1. Verificación de Permisos (deben ser < 644)
        try:
            file_stat = os.stat(log_path)
            permissions = oct(file_stat.st_mode)[-3:]
            if int(permissions) > 644:
                status = "FALLA"
                details.append(f"Permisos inseguros ({permissions}). Se requiere 600 o 640.")
            else:
                details.append(f"Permisos correctos ({permissions}).")
        except Exception as e:
            status = "ERROR"
            details.append(f"Error leyendo permisos: {str(e)}")

        # 2. Verificación de Inmutabilidad (+a)
        # Requiere herramienta 'lsattr' (e2fsprogs)
        if shutil.which('lsattr'):
            try:
                result = subprocess.run(['lsattr', log_path], capture_output=True, text=True)
                attributes = result.stdout.split()[0] if result.stdout else ""
                
                if 'a' in attributes:
                    details.append("Atributo 'append-only' (+a) ACTIVO.")
                else:
                    status = "ADVERTENCIA" # Falla parcial
                    details.append("Falta atributo (+a). Logs vulnerables a borrado por root.")
            except Exception as e:
                details.append(f"Error ejecutando lsattr: {str(e)}")
        else:
            details.append("Herramienta 'lsattr' no instalada. No se puede verificar inmutabilidad.")

        findings.append({
            "recurso": log_path,
            "estado": status,
            "detalles": "; ".join(details)
        })

    overall_status = "FALLA" if any(f['estado'] == "FALLA" for f in findings) else "CUMPLE"
    if not log_found: overall_status = "ERROR"

    return {
        "control": "TECH_LOG_003",
        "estado": overall_status,
        "evidencia": findings if log_found else "No se encontraron logs estándar."
    }

def check_disk_encryption():
    """
    Simulación: Verifica si el disco raíz está encriptado (LUKS/BitLocker).
    """
    # Aquí iría la lógica real con 'lsblk' o 'manage-bde'
    return {
        "control": "TECH_ENC_001",
        "estado": "ADVERTENCIA", # Simulado para demostración
        "evidencia": "No se pudo verificar encriptación LUKS en partición /root."
    }

def check_ssh_root_login():
    """
    Simulación: Verifica configuración de SSH.
    """
    return {
        "control": "TECH_ACC_002",
        "estado": "CUMPLE", # Simulado
        "evidencia": "PermitRootLogin configurado en 'no'."
    }
