import os
import requests
import urllib3
import json
from dotenv import load_dotenv
from google import genai

# Desactivar advertencias de seguridad por el certificado autofirmado local
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Leer las credenciales de la caja fuerte virtual
load_dotenv()
WAZUH_IP = os.getenv("WAZUH_IP")
WAZUH_USER = os.getenv("WAZUH_USER")
WAZUH_PASSWORD = os.getenv("WAZUH_PASSWORD")

# Credenciales para la base de datos
INDEXER_USER = os.getenv("INDEXER_USER")
INDEXER_PASSWORD = os.getenv("INDEXER_PASSWORD")

# Credenciales IA
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

def obtener_token():
    """Plano de Control: Obtenemos el token en el puerto 55000"""
    print("[*] Autenticando en Wazuh Manager (Plano de Control - P. 55000)...")
    url = f"https://{WAZUH_IP}:55000/security/user/authenticate"
    try:
        response = requests.get(url, auth=(WAZUH_USER, WAZUH_PASSWORD), verify=False)
        if response.status_code == 200:
            return response.json()['data']['token']
        return None
    except Exception:
        return None

def analizar_con_ia(payload):
    """Fase 3: Análisis automatizado con Inteligencia Artificial (Gemini SDK Nuevo)"""
    print("\n=== INICIANDO ANÁLISIS CON INTELIGENCIA ARTIFICIAL (GEMINI) ===")
    
    # 1. Creamos el cliente centralizado según la nueva documentación
    client = genai.Client(api_key=GEMINI_API_KEY)
    
    system_prompt = """Actúa como un analista SOC L3 experto. 
    Tu tarea es analizar el siguiente bloque de alertas de seguridad extraídas de un SIEM Wazuh. 
    Debes:
    1. Identificar si existe un patrón de ataque evidente (ej. fuerza bruta, enumeración).
    2. Extraer de forma precisa la IP ofensiva principal.
    3. Generar el comando exacto de 'iptables' para bloquear esa IP a nivel de red.
    Responde de forma técnica, estructurada, determinista y directa. No alucines comandos."""

    prompt_final = f"{system_prompt}\n\n=== LOGS DEL SIEM ===\n{payload}"

    try:
        # 2. Llamamos a la API con la nueva estructura
        response = client.models.generate_content(
            model='gemini-3.5-flash',
            contents=prompt_final
        )
        
        print("\n[+] Reporte L3 Generado por la IA:\n")
        print(response.text)
        
    except Exception as e:
        print(f"[-] Error de conexión con la API de Gemini: {e}")

def obtener_alertas():
    """Plano de Datos: Consultamos el Indexer a través del túnel SSH"""
    print("[*] Conectando a la Base de Datos (Wazuh Indexer - P. 9200)...")
    url = f"https://127.0.0.1:9200/wazuh-alerts-*/_search"
    
    query = {
        "query": {
            "range": {
                "timestamp": {
                    "gte": "now-7d"
                }
            }
        },
        "size": 150 
    }
    
    try:
        response = requests.get(
            url, 
            auth=(INDEXER_USER, INDEXER_PASSWORD), 
            json=query, 
            verify=False
        )
        
        if response.status_code == 200:
            print("[+] ¡Alertas extraídas con éxito!\n")
            payload = response.json()
            alertas_aisladas = payload.get("hits", {}).get("hits", [])
            
            print("=== INICIANDO PARSEO DE ALERTAS ===")
            
            reporte_incidente = "Contexto de Seguridad del SIEM Wazuh:\n"
            reporte_incidente += "Por favor, analiza el siguiente bloque de eventos y genera un resumen ejecutivo indicando si hay un posible ataque de fuerza bruta.\n\n"
            
            for evento in alertas_aisladas:
                source = evento.get("_source", {})
                data = source.get("data", {})
                rule = source.get("rule", {})
                mitre = rule.get("mitre", {})
                
                ip_origen = data.get("srcip", "IP Desconocida")
                usuario = data.get("dstuser", "Usuario Desconocido")
                puerto = data.get("srcport", "Puerto Desconocido")
                descripcion = rule.get("description", "Sin descripción")
                tactica_mitre = mitre.get("tactic", ["Sin táctica"])[0]
                
                hora_cruda = source.get("@timestamp", "Hora desconocida")
                hora_evento = hora_cruda.replace("T", " ")[:19] if hora_cruda != "Hora desconocida" else hora_cruda
                
                # 1. Empaquetado silencioso para la IA
                linea_alerta = f"[{hora_evento}] Evento detectado: {descripcion} | Táctica MITRE: {tactica_mitre} | IP Origen: {ip_origen} | Puerto: {puerto} | Usuario Objetivo: {usuario}\n"
                reporte_incidente += linea_alerta
                
                # 2. Visualización limpia en terminal
                print(f"[*] Alerta detectada:")
                print(f"    - Hora: {hora_evento}")
                print(f"    - IP Atacante: {ip_origen}")
                print(f"    - Usuario Objetivo: {usuario}")
                print(f"    - Puerto: {puerto}")
                print(f"    - Detalle: {descripcion}")
                print(f"    - Táctica MITRE: {tactica_mitre}\n")
                
            print("\n=== PAYLOAD LISTO PARA INYECTAR A LA IA ===")

            # 3. Llamada al cerebro de IA
            if reporte_incidente.strip() != "":
                analizar_con_ia(reporte_incidente)

        else:
            print(f"[-] Error HTTP {response.status_code}: {response.text}")
            
    except Exception as e:
        print(f"[-] Error crítico de red: {e}")

# EL GATILLO PRINCIPAL (UNA SOLA VEZ AL FINAL)
if __name__ == "__main__":
    print("=== INICIANDO AGENTE SOC ===")
    token_jwt = obtener_token()
    if token_jwt:
        print("[+] Token maestro asegurado en memoria.")
    
    obtener_alertas()