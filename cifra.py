from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from unidecode import unidecode

alfabeto_original = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
alfabeto_alternativo = "AHBKCWDEFLMNRSGIYJOPQTUVXZ"

def cifrar_mensagem(frase):
    frase_cifrada = ''
    for letra in frase:
        if letra in alfabeto_original:
            indice = alfabeto_original.index(letra)
            frase_cifrada += alfabeto_alternativo[indice]
        else:
            frase_cifrada += letra
    return frase_cifrada

def decifrar_mensagem(frase_cifrada):
    frase_decifrada = ''
    for letra in frase_cifrada:
        if letra in alfabeto_alternativo:
            indice = alfabeto_alternativo.index(letra)
            frase_decifrada += alfabeto_original[indice]
        else:
            frase_decifrada += letra
    return frase_decifrada


def gerar_chaves_rsa():
    chave = RSA.generate(2048)
    chave_privada = chave.export_key("DER")  # DER ou .der: formato binário muito usado para armazenar chaves criptográficas
    chave_publica = chave.publickey().export_key("DER")
    return chave_privada, chave_publica

def criptografar_rsa(mensagem, chave_publica):
    chave = RSA.import_key(chave_publica)
    cifra = PKCS1_OAEP.new(chave) # inicializar um objeto de cifragem
    return cifra.encrypt(mensagem.encode())  # Retorna em bytes 

def descriptografar_rsa(mensagem_cifrada, chave_privada):
    chave = RSA.import_key(chave_privada)
    cifra = PKCS1_OAEP.new(chave)
    return cifra.decrypt(mensagem_cifrada).decode() # Retorna string 

# Gerar chaves RSA
chave_privada, chave_publica = gerar_chaves_rsa()

# Entrada feita pelo usuário
frase = input("\nInforme uma frase (SEM CARACTERES ESPECIAIS): ")
frase_sem_acentos = unidecode(frase).upper()
cifrada = cifrar_mensagem(frase_sem_acentos)

print(f"\nFrase cifrada (alfabeto alternativo): {cifrada}")

print(f"\n\nChave pública RSA: {chave_publica}") # Em bytes
print(f"\n\nChave privada RSA: {chave_privada}") # Em bytes

# Criptografando a mensagem cifrada com RSA
mensagem_criptografada = criptografar_rsa(cifrada, chave_publica)
print(f"\nMensagem criptografada com RSA (bytes): {mensagem_criptografada}")

# Descriptografando a mensagem
mensagem_decifrada_rsa = descriptografar_rsa(mensagem_criptografada, chave_privada)
decifrada = decifrar_mensagem(mensagem_decifrada_rsa)
print(f"\nMensagem decifrada: {decifrada}")
