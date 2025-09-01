import sys

def cifrado_cesar(texto, corrimiento):
    resultado = ""
    for caracter in texto:
        if caracter.isalpha():
            base = ord('A') if caracter.isupper() else ord('a')
            resultado += chr((ord(caracter) - base + corrimiento) % 26 + base)
        else:
            resultado += caracter
    return resultado

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python3 cesar.py \"texto\" corrimiento")
        sys.exit(1)

    texto = sys.argv[1]
    corrimiento = int(sys.argv[2])

    texto_cifrado = cifrado_cesar(texto, corrimiento)
    print(texto_cifrado)
