import hashlib

# Función para descifrar un mensaje cifrado utilizando el cifrado Vigenère
def descifrar_vigenere(mensaje_cifrado, clave):
    texto_decifrado = ""
    clave_extendida = clave * (len(mensaje_cifrado) // len(clave)) + clave[:len(mensaje_cifrado) % len(clave)]
    for i in range(len(mensaje_cifrado)):
        if mensaje_cifrado[i].isalpha():
            desplazamiento_clave = ord(clave_extendida[i].upper()) - ord('A')

            if mensaje_cifrado[i].islower():
                # Cifrar letra minúscula
                texto_decifrado += chr(((ord(mensaje_cifrado[i]) - ord('a') - desplazamiento_clave) % 26) + ord('a'))
            else:
                # Cifrar letra mayúscula
                texto_decifrado += chr(((ord(mensaje_cifrado[i]) - ord('A') - desplazamiento_clave) % 26) + ord('A'))
        else:
            # Mantener caracteres no alfabéticos sin cambios
            texto_decifrado += mensaje_cifrado[i]

    return texto_decifrado

def generar_hash(mensaje):
    sha256 = hashlib.sha256()
    sha256.update(mensaje.encode())
    return sha256.hexdigest()

# Función para deshacer la operación de RSP
def rsp(mensaje_cifrado, clave_rsp):
    mensaje_rsp = ""
    bloque_size = 8  # Tamaño del bloque en bytes

    for i in range(0, len(mensaje_cifrado), bloque_size):
        bloque = mensaje_cifrado[i:i + bloque_size]
        bloque_xor = "".join([chr(ord(b) ^ ord(k)) for b, k in zip(bloque, clave_rsp)])
        mensaje_rsp += bloque_xor
        print(f"Bloque cifrado: {bloque}")
        print(f"Bloque XOR: {bloque_xor}")
        print(f"Mensaje descifrado parcial: {mensaje_rsp}")
    return mensaje_rsp


# Archivo con el mensaje cifrado y el hash original
archivo_entrada = "C:/Users/bsoto/OneDrive/Escritorio/Trabajos U/2023_2/Seguridad Informatica/Lab2_BastianSoto/mensajeseguro.txt"
clave = "bastian"
clave_rsp = "clavespn"

# Abrir y leer el archivo
with open(archivo_entrada, "r") as archivo:
    contenido = archivo.read()


# Dividir el contenido en las partes correspondientes
mensaje_cifrado = contenido.split("\n\nHASH ORIGINAL:\n")[0].split("MENSAJE CIFRADO:\n")[1]
print(mensaje_cifrado)
hash_original = contenido.split("\n\nHASH ORIGINAL:\n")[1]
print(hash_original)
# Descifrar el mensaje cifrado con RSP
mensaje_descifrado_rsp = rsp(mensaje_cifrado, clave_rsp)
print(mensaje_descifrado_rsp)
# Descifrar el mensaje original
mensaje_descifrado_vigenere = descifrar_vigenere(mensaje_descifrado_rsp,clave)
print("Mensaje Descifrado con Vigenère:\n", mensaje_descifrado_vigenere)

# Calcular el hash del mensaje descifrado
hash_descifrado = generar_hash(mensaje_descifrado_vigenere)
print(hash_descifrado)
# Verificar la integridad del mensaje
if hash_descifrado == hash_original:
    print("El mensaje se descifró correctamente y su integridad está verificada.")
    print("Mensaje Descifrado con RSP:\n", mensaje_descifrado_rsp)
else:
    print("La integridad del mensaje no se pudo verificar. El mensaje podría haber sido modificado.")



