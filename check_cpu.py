import psutil
import datetime

"""Author : Gonzalo Fernandez"""

def obtener_consumo_recursos():
    """
    Obtiene el consumo de CPU, memoria y disco del sistema.
    """
    uso_cpu = psutil.cpu_percent(interval=1)
    uso_memoria = psutil.virtual_memory().percent
    uso_disco = psutil.disk_usage('/').percent
    
    return uso_cpu, uso_memoria, uso_disco

def obtener_procesos_conexiones(porcentaje_limite, recurso):
    """
    Obtiene los procesos que exceden el porcentaje de consumo de un recurso especificado.
    Retorna una lista de tuplas (nombre del proceso, PID, puertos abiertos).
    """
    procesos = []
    
    for proceso in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'connections']):
        if recurso == 'cpu' and proceso.info['cpu_percent'] > porcentaje_limite:
            puertos = [c.laddr.port for c in proceso.info['connections'] if c.status == 'LISTEN']
            if puertos:
                procesos.append((proceso.info['name'], proceso.info['pid'], puertos))
        
        if recurso == 'memoria' and proceso.info['memory_percent'] > porcentaje_limite:
            puertos = [c.laddr.port for c in proceso.info['connections'] if c.status == 'LISTEN']
            if puertos:
                procesos.append((proceso.info['name'], proceso.info['pid'], puertos))
        
        if recurso == 'disco':
            try:
                uso_disco = psutil.disk_usage('/').percent
                if uso_disco > porcentaje_limite:
                    puertos = [c.laddr.port for c in proceso.info['connections'] if c.status == 'LISTEN']
                    if puertos:
                        procesos.append((proceso.info['name'], proceso.info['pid'], puertos))
            except KeyError:
                continue
    
    return procesos

def mostrar_alerta(recursos):
    """
    Muestra una alerta con la información de los procesos que exceden los límites de consumo.
    """
    fecha_actual = datetime.datetime.now()
    mensaje = f"Alerta: Uso alto de recursos - Fecha y hora: {fecha_actual}\n"
    
    for recurso, porcentaje_limite in recursos.items():
        if recurso == 'cpu':
            uso_recurso = obtener_consumo_recursos()[0]
        elif recurso == 'memoria':
            uso_recurso = obtener_consumo_recursos()[1]
        elif recurso == 'disco':
            uso_recurso = obtener_consumo_recursos()[2]
        else:
            print(f"Recurso no válido: {recurso}")
            continue
        
        if uso_recurso > porcentaje_limite:
            mensaje += f"Recursos: {recurso.upper()} - Uso: {uso_recurso}%\n"
            procesos = obtener_procesos_conexiones(porcentaje_limite, recurso)
            
            for proceso in procesos:
                mensaje += f"Proceso: {proceso[0]} (PID: {proceso[1]}) - Puertos: {proceso[2]}\n"
    
    print(mensaje)

# Definir los límites de actividad
recursos_limite = {
    'cpu': 80,  # Porcentaje de uso de CPU
    'memoria': 80,  # Porcentaje de uso de memoria
    'disco': 80  # Porcentaje de uso de disco
}

# Mostrar alerta si se superan los límites de consumo
mostrar_alerta(recursos_limite)
