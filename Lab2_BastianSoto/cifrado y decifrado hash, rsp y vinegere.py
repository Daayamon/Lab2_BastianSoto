import hashlib

def cifrar_vigenere(texto, clave):
    texto_cifrado1 = ""
    clave_extendida = clave * (len(texto) // len(clave)) + clave[:len(texto) % len(clave)]
    for i in range(len(texto)):
        if texto[i].isalpha():
            desplazamiento_clave = ord(clave_extendida[i].upper()) - ord('A')

            if texto[i].islower():
                # Cifrar letra minúscula
                texto_cifrado1 += chr(((ord(texto[i]) - ord('a') + desplazamiento_clave) % 26) + ord('a'))
            else:
                # Cifrar letra mayúscula
                texto_cifrado1 += chr(((ord(texto[i]) - ord('A') + desplazamiento_clave) % 26) + ord('A'))
        else:
            # Mantener caracteres no alfabéticos sin cambios
            texto_cifrado1 += texto[i]

    return texto_cifrado1

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

##rsp (red sustitucion permutacion)
def rsp(mensaje_cifrado, clave_rsp):
    mensaje_rsp = ""
    bloque_size = 8  # Tamaño del bloque en bytes

    for i in range(0, len(mensaje_cifrado), bloque_size):
        bloque = mensaje_cifrado[i:i + bloque_size]
        bloque_xor = "".join([chr(ord(b) ^ ord(k)) for b, k in zip(bloque, clave_rsp)])
        mensaje_rsp += bloque_xor
        
    return mensaje_rsp

def descifrar_rsp(mensaje_cifrado_rsp, clave_rsp):
    mensaje_descifrado = ""
    bloque_size = 8  # Tamaño del bloque en bytes

    for i in range(0, len(mensaje_cifrado_rsp), bloque_size):
        bloque = mensaje_cifrado_rsp[i:i + bloque_size]
        bloque_descifrado = "".join([chr(ord(b) ^ ord(k)) for b, k in zip(bloque, clave_rsp)])
        mensaje_descifrado += bloque_descifrado

    return mensaje_descifrado


archivo_entrada = "C:/Users/bsoto/OneDrive/Escritorio/Trabajos U/2023_2/Seguridad Informatica/Lab2_BastianSoto/mensajedeentrada.txt"
clave = "bastian"
clave_rsp = "clavespn"

with open(archivo_entrada, "r") as archivo:
    mensaje_original = archivo.read()
    
# Generar el hash del mensaje
hash_original = generar_hash(mensaje_original)
# Cifrado del mensaje
mensaje_cifrado_v = cifrar_vigenere(mensaje_original, clave)
print(mensaje_cifrado_v)


# cifrado de red rsp al mensaje 
mensaje_cifrado_rsp = rsp(mensaje_cifrado_v, clave_rsp)
print(mensaje_cifrado_rsp)
# Guardar el mensaje cifrado y el hash en un archivo y cifrado rsp
with open("mensajeseguro.txt", "w") as archivo_salida:
    archivo_salida.write(f"MENSAJE CIFRADO:\n{mensaje_cifrado_rsp}\n\nHASH ORIGINAL:\n{hash_original}")

print("Mensaje cifrado y hash generado correctamente.")
#########################################################################################################################
# Decifrado
# Descifrar el mensaje cifrado RSP
mensaje_descifrado_rsp = descifrar_rsp(mensaje_cifrado_rsp, clave_rsp)
print(mensaje_descifrado_rsp)
# Descifrar el mensaje original
mensaje_descifrado_vigenere = descifrar_vigenere(mensaje_descifrado_rsp,clave)
print("Mensaje Descifrado con Vigenère: ", mensaje_descifrado_vigenere)

# Calcular el hash del mensaje descifrado
hash_descifrado = generar_hash(mensaje_descifrado_vigenere)


# Verificar la integridad del mensaje
if hash_descifrado == hash_original:
    print("El mensaje se descifró correctamente y su integridad está verificada.")
    print("Mensaje Descifrado con RSP:", mensaje_descifrado_rsp)
else:
    print("La integridad del mensaje no se pudo verificar. El mensaje podría haber sido modificado.")
