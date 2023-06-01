import hashlib

"""Author : Gonzalo Fernandez"""

def calcular_hash(archivo):
    """
    Calcula el hash MD5 de un archivo.
    """
    hash_md5 = hashlib.md5()
    with open(archivo, "rb") as f:
        for bloque in iter(lambda: f.read(4096), b""):
            hash_md5.update(bloque)
    return hash_md5.hexdigest()

def verificar_integridad(archivos):
    """
    Verifica la integridad de los archivos mediante el cálculo de hash.
    """
    for archivo in archivos:
        hash_guardado = obtener_hash_guardado(archivo)
        hash_actual = calcular_hash(archivo)

        if hash_guardado:
            if hash_actual == hash_guardado:
                print(f"El archivo {archivo} no ha sido modificado.")
            else:
                print(f"El archivo {archivo} ha sido modificado.")
        else:
            guardar_hash(archivo, hash_actual)
            print(f"Se ha guardado el hash del archivo {archivo}.")

def obtener_hash_guardado(archivo):
    """
    Obtiene el hash guardado anteriormente para un archivo.
    """
    # Aquí puedes implementar la lógica para obtener el hash guardado, por ejemplo, desde un archivo o una base de datos
    return None

def guardar_hash(archivo, hash):
    """
    Guarda el hash calculado de un archivo.
    """
    # Aquí puedes implementar la lógica para guardar el hash, por ejemplo, en un archivo o una base de datos
    pass

# Solicitar al usuario el archivo de verificación
archivo_verificacion = input("Ingrese el archivo a verificar: ")

# Verificar integridad del archivo
verificar_integridad([archivo_verificacion])

