# 🛡️ AI SOC Agent: Wazuh & Gemini Integration

Un agente de respuesta a incidentes que extrae datos de un SIEM Wazuh, utiliza Inteligencia Artificial (Gemini 3.5) para análisis L3 determinista, y genera reglas de mitigación a nivel de red (iptables) en tiempo real.

## ⚙️ Arquitectura del Proyecto

* **SIEM:** Wazuh Indexer (Extracción de logs JSON mediante API HTTP).
* **Inteligencia Artificial:** SDK `google-genai` (Modelo Gemini-3.5-Flash para análisis determinista).
* **Lenguaje:** Python 3.11+
* **Vector de Ataque Simulado:** T1110.001 (Fuerza Bruta SSH) utilizando Hydra.

## 🚀 Flujo de Ejecución (Prueba de Concepto - PoC)

1. **Ataque Activo:** Una máquina ofensiva (Kali Linux) ejecuta un ataque de fuerza bruta contra el puerto 22 de un endpoint monitoreado.
2. **Ingesta:** El agente de Wazuh detecta los fallos de autenticación de PAM (`sshd: authentication failed`) y alerta al servidor central.
3. **Extracción y Parseo:** El script en Python intercepta la base de datos NoSQL de Wazuh, limpia las marcas de tiempo ISO 8601 y extrae el payload crudo.
4. **Análisis L3 (IA):** Se inyecta un *System Prompt* al modelo de lenguaje. La IA identifica la táctica MITRE, extrae la IP ofensiva de los logs y diferencia entre atacantes y administradores legítimos.
5. **Recomendación de Mitigación (Human-in-the-Loop):** El sistema **no ejecuta bloqueos automáticos**. Actúa estrictamente en modo asesor, sugiriendo el comando exacto (`sudo iptables -I INPUT 1 -s <IP> -j DROP`) para que el analista humano valide y aplique la regla en el firewall.

## 🛠️ Instalación y Uso

1. Clonar el repositorio:
   ```bash
   git clone https://github.com/Italo21-DH/Wazuh-AI-SOC-Agent.git