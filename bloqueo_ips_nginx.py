"""Author : Gonzalo Fernandez"""

import io
import pandas as pd
import paramiko
import scp
import os
import subprocess
import socket
import maxminddb
import colorama
from colorama import Fore, Style
import time
import getpass
from datetime import datetime, timedelta
import datetime


def filter_logs(filename):

    # Obtener el usuario actual
    current_user = os.getlogin()

    # Ejecutar el comando con `sudo` para filtrar los logs de autenticación
    command = f"sudo -u {current_user} cat /var/log/nginx/access.log | grep '{hours_ago_formatted}' | grep -E ' 400 | 429'"
    logs = subprocess.check_output(command, shell=True).decode().strip()
    count = logs.count('\n')

    if logs:
        with open(filename, "w") as file:
            file.write(logs)
        print(f"{count} con errores 400 y 429. Los logs se han guardado en {filename}")
    else:
        print("No se encontraron logs de autenticación con error 400 o 429 en la última hora")



def recopilar_datos():
    while True:
        try:
            host = input("Ingrese la dirección IP del host: ")
            name = input("Ingrese el nombre de usuario: ")
            password = getpass.getpass("Ingrese la contraseña del usuario: ") 
            port = 22
            return host, name, password, port
        except Exception as e:
            print(f"Ocurrió un error: {e}")
            print("Inténtelo de nuevo.")


def conectar(host, name, password, port=22):
    while True:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(host, port, name, password)
            return client
        except paramiko.ssh_exception.AuthenticationException:
            print("Error de autenticación. Por favor, verifique sus credenciales e inténtelo de nuevo.")
            return
        except Exception as e:
            print(f"Ocurrió un error: {e}")
            print("Inténtelo de nuevo.")

def execute_download():
    datos = recopilar_datos()
    if datos is None:
        return

    host, name, password, port = datos
    ssh_client = conectar(host, name, password, port)
    if ssh_client is None:
        return

    while True:
        try:
            stdin, stdout, stderr = filter_logs("attack_ips.csv")
            salida = stdout.read().decode()
            errores = stderr.read().decode()
            with scp.SCPClient(ssh_client.get_transport()) as scp_client:
                scp_client.get('attack_ips.csv')
            if len(errores) > 0:
                print("Se produjeron errores al ejecutar el comando:")
                print(errores)
            else:
                print(f'{Fore.BLUE}Agregando Totales De Conexiones Ips:{Style.RESET_ALL}', end='')
                print(salida)
        except Exception as e:
            print(f"Ocurrió un error: {e}")
            print("Inténtelo de nuevo.")
        else:
            break
    ssh_client.close()

execute_download()

print("Enriqueciendo Contextos De Ip.")

def process_csv_file():
    try:
        # Leer archivo CSV y procesar datos
        csv_file = 'attack_ips.csv'
        df = pd.read_csv('attack_ips.csv', sep=' ', header=None, names=['ip', 'dash1', 'dash2', 'fecha', 'offset', 'metodo', 'url', 'protocolo', 'status', 'bytes', 'dash3', 'user_agent'])
        df.drop(['dash1', 'dash2', 'offset', 'url', 'protocolo', 'dash3'], axis=1, inplace=True)
        df['fecha'] = df['fecha'].str.replace('[','')
        
        df['fecha'] = pd.to_datetime(df['fecha'], format='%d/%b/%Y:%H:%M:%S')
    
        
        # obtener la fecha y hora actual 
        now = datetime.now()

        # restar una hora para obtener la hora límite
        last_hour = now - timedelta(hours=1)

        # seleccionar solo las filas que estén dentro de la última hora
        df = df[df['fecha'] > last_hour]
        #df = df.reset_index(drop=True)
        ip_counts = df['ip'].value_counts().reset_index()
        ip_counts.columns = ['ip', 'ip_count']
        n_filas_original = len(df)
        df = df.merge(ip_counts, on='ip', how='left')
        df.drop_duplicates(subset=['ip'], inplace=True)
        df = df.query('ip_count > 5')
        n_filas_nuevo = len(df)
        n_duplicados_eliminados = n_filas_original - n_filas_nuevo
        print(f"{Fore.BLUE}Se eliminaron {n_duplicados_eliminados} IP duplicadas.{Style.RESET_ALL} ", end='')

        # Filtrar IPs y generar logs
        df_ips = df[['ip']].copy()

        #
        mmdb_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'GeoLite2-ASN.mmdb')
        reader = maxminddb.open_database(mmdb_path)
        df['location'] = df['ip'].apply(lambda x: reader.get(x))
        df['location'] = df['location'].astype(str)
        df[['asn_number', 'asn_organization']] = df['location'].apply(lambda x: pd.Series(eval(x)))
        ips_excluidos = len(df[~df['asn_number'].isin(asn_filtro)])
        time.sleep(3)

        # Generar logs
        df_logs = df[~df['asn_number'].isin(asn_filtro)]
        df_logs = df_logs.drop('location', axis=1)
        print(df_logs)
        df_logs.to_csv('ips_hora.csv', index=False)
        df_block = pd.read_csv('ips_hora.csv')
    
        # Seleccionar solo la columna de IP
        df_block = df_block[['ip']]
        print(f"{Fore.BLUE}bloqueando la siguiente ips.{Style.RESET_ALL} ")
        print(df_block)
        df_block.dropna(how='all', inplace=True)
        #df_block = df_block[['ip']]

        # Guardar IPs en un archivo de texto
        df_block.to_csv('ips.csv', header=False, index=False)
    except Exception as e:
        print(f"Se produjo una excepción: {e}")
        return None

    return df_logs

process_csv_file()

def is_ip_blocked(ip, ssh_client):
    stdin, stdout, stderr = ssh_client.exec_command(f"iptables -L -n | grep {ip}")
    output = stdout.read().decode()
    return ip in output

def block_ips(csv_file, ssh_client):
    df = pd.read_csv(csv_file)
    ips = df['ip'].tolist()
    blocked_ips = []
    for ip in ips:
        if not is_ip_blocked(ip, ssh_client):
            ssh_client.exec_command(f"sudo iptables -A INPUT -s {ip} -j DROP")
            ssh_client.exec_command(f"sudo iptables -A OUTPUT -d {ip} -j DROP")
            blocked_ips.append(ip)

    if blocked_ips:
        print(f"Blocked IP addresses: {', '.join(blocked_ips)}")
    else:
        print("No new IP addresses blocked.")

# Sube CSV comprueba si las ips dentro del csv estan dentro de la regla de iptables si no esta pasa a bloquear

def execute_upload():
    datos = recopilar_datos()
    if datos is None:
        return

    host, name, password, port = datos
    ssh_client = conectar(host, name, password, port)
    if ssh_client is None:
        return

    with ssh_client:
        with scp.SCPClient(ssh_client.get_transport()) as scp_client:
            local_file = 'ips.csv'
            remote_home = input("Enter the remote home directory: ")
            remote_path = os.path.join(remote_home, os.path.basename(local_file))
            scp_client.put(local_file, remote_path)

            block_ips(remote_path, ssh_client)
            print("IPs Bloqueadas Con Éxito. ¡Adiós!")
    ssh_client.close()

execute_upload()
