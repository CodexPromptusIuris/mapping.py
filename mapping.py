"""
MAPPING.PY - El Corazón Legal del Auditor
Autor: CodexPromptusIuris
Descripción: Vincula normas jurídicas (Chile/ISO) con funciones técnicas de validación.
"""

# Importamos las funciones técnicas (simuladas aquí, deben estar en tus otros scripts)
# from validations import check_encryption, check_ssh_root, check_backup_policy

class ComplianceMapper:
    def __init__(self):
        # BASE DE CONOCIMIENTO LEGAL-TÉCNICA
        self.control_map = {
            # ---------------------------------------------------------
            # CONTROL 1: ENCRIPTACIÓN DE DATOS (Protección de la Información)
            # ---------------------------------------------------------
            "TECH_ENC_001": {
                "nombre_tecnico": "Validación de Encriptación de Disco (AES-256)",
                "funcion_python": "check_disk_encryption", # Nombre de tu función real
                "normativas_asociadas": [
                    {
                        "norma": "ISO/IEC 27001:2013",
                        "control": "A.10.1.1",
                        "descripcion": "Política sobre el uso de controles criptográficos."
                    },
                    {
                        "norma": "Ley 21.719 (Chile) / Ley 21.459",
                        "articulo": "Art. 4 - Acceso Ilícito y Protección de Datos",
                        "descripcion": "Obligación de establecer medidas de seguridad para impedir acceso no autorizado a datos sensibles.",
                        "sancion_asociada": "Presidio menor en su grado mínimo a medio."
                    },
                    {
                        "norma": "Reglamento Ciberseguridad",
                        "articulo": "Art. 7 - Integridad y Confidencialidad",
                        "descripcion": "Los datos en reposo deben mantener atributos de confidencialidad mediante cifrado."
                    }
                ]
            },
            
            # ---------------------------------------------------------
            # CONTROL 2: GESTIÓN DE ACCESOS (SSH ROOT)
            # ---------------------------------------------------------
            "TECH_ACC_002": {
                "nombre_tecnico": "Verificación de Acceso Root SSH Deshabilitado",
                "funcion_python": "check_ssh_root_login",
                "normativas_asociadas": [
                    {
                        "norma": "ISO/IEC 27001:2013",
                        "control": "A.9.2.3",
                        "descripcion": "Gestión de derechos de acceso privilegiado."
                    },
                    {
                        "norma": "Ley 21.459 (Delitos Informáticos)",
                        "articulo": "Art. 2 - Acceso Ilícito",
                        "descripcion": "El que sin autorización supere barreras técnicas de acceso.",
                        "nota_legal": "Mantener root abierto facilita la comisión del delito por terceros (culpa in vigilando)."
                    }
                ]
            },

            # ---------------------------------------------------------
            # CONTROL 3: INTEGRIDAD DEL SISTEMA (LOGS)
            # ---------------------------------------------------------
            "TECH_LOG_003": {
                "nombre_tecnico": "Inmutabilidad de Logs de Auditoría",
                "funcion_python": "check_log_immutability",
                "normativas_asociadas": [
                    {
                        "norma": "Ley 21.719 (Modifica cuerpos legales)",
                        "articulo": "Art. X (Referencial)", 
                        "descripcion": "Deber de mantener registros fidedignos para auditoría forense.",
                        # *Nota: Aquí integras el texto específico del PDF que subiste*
                    }
                ]
            }
        }

    def obtener_controles(self):
        return self.control_map

    def generar_matriz_legal(self):
        """
        Genera un reporte de qué leyes se están cubriendo con los scripts actuales.
        Útil para vender el software a gerentes legales.
        """
        matriz = {}
        for tech_id, datos in self.control_map.items():
            for norma in datos['normativas_asociadas']:
                nombre_norma = norma['norma']
                if nombre_norma not in matriz:
                    matriz[nombre_norma] = []
                matriz[nombre_norma].append(f"{tech_id}: {norma.get('articulo', norma.get('control'))}")
        return matriz

# ---------------------------------------------------------
# EJEMPLO DE USO (Simulación de Ejecución)
# ---------------------------------------------------------

if __name__ == "__main__":
    mapper = ComplianceMapper()
    
    # 1. El sistema técnico ejecuta un chequeo
    resultado_tecnico = "FAIL" # Imaginemos que el script detectó que el disco NO está encriptado
    id_control_ejecutado = "TECH_ENC_001"
    
    # 2. El mapper traduce ese fallo técnico a riesgo legal
    info_control = mapper.obtener_controles().get(id_control_ejecutado)
    
    print(f"🛑 ALERTA DE CIBERSEGURIDAD: {info_control['nombre_tecnico']}")
    print(f"Estado Técnico: {resultado_tecnico}")
    print("\n⚖️ IMPLICANCIAS LEGALES (CHILE & ISO):")
    
    for normativa in info_control['normativas_asociadas']:
        print(f"   - [{normativa['norma']}] -> {normativa.get('articulo', normativa.get('control'))}")
        print(f"     RIESGO: {normativa['descripcion']}")
        if 'sancion_asociada' in normativa:
            print(f"     ⚠️ SANCIÓN POSIBLE: {normativa['sancion_asociada']}")
        print("---")
