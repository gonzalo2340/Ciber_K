import json
import requests
from colorama import Fore, Style
from tabulate import tabulate

# Constantes para configuración
API_KEY = ""
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Función para consultar CVE por CPE
def consultar_cve_por_cpe(cpe_name):
    headers = {"X-Api-Key": API_KEY}
    params = {"cpeName": cpe_name}
    try:
        respuesta = requests.get(NVD_API_URL, headers=headers, params=params)
        respuesta.raise_for_status()
    except requests.HTTPError as error:
        print(f"Error al consultar la API: {error}")
        return None
    else:
        return respuesta.json()

# Función para extraer información relevante de las vulnerabilidades
def extraer_informacion_vulnerabilidades(vulnerabilidades):
    datos = []
    total_cve_ws2016 = 0

    for i, vulnerabilidad in enumerate(vulnerabilidades):
        if i < 5:
            try:
                id_corto = vulnerabilidad["cve"]["id"]
                base_severity = vulnerabilidad["cve"]["metrics"]["cvssMetricV2"][0]["baseSeverity"]
                accion = vulnerabilidad["cve"].get("cisaRequiredAction", "I don't required actions").split()[1]
                color = Fore.RED if base_severity == "HIGH" else Fore.ORANGE if base_severity == "MEDIUM" else Fore.GREEN
                os = "Windows Server 2016"
            except KeyError as error:
                print(f"Error al obtener información de la vulnerabilidad: {error}")
            else:
                datos.append([
                    id_corto,
                    color + base_severity + Style.RESET_ALL,
                    vulnerabilidad["cve"].get("cisaVulnerabilityName", "Sin nombre CISA"),
                    accion,
                    os
                ])

        total_cve_ws2016 += 1

    return datos, total_cve_ws2016

if __name__ == "__main__":
    # Ejemplo de uso
    cpe_name = "cpe:2.3:o:microsoft:windows_server_2016:-:*:*:*:*:*:*:*"
    json_data = consultar_cve_por_cpe(cpe_name)

    if json_data:
        vulnerabilidades = json_data["vulnerabilities"]
        datos, total_cve_ws2016 = extraer_informacion_vulnerabilidades(vulnerabilidades)

        print(tabulate(datos, headers=["ID", "Severity", "Vulnerability Name", "Action", "OS"]))
        print(f"\nTotal de CVE para Windows Server 2016: {total_cve_ws2016}")
