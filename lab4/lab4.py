from Crypto.Cipher import DES, AES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import DES3 as TDES
import base64
import sys

def print_sep(title):
    print("\n" + "-" * 5, title, "-" * 5)

def to_hex(b: bytes) -> str:
    return b.hex()

def to_b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def ajustar_bytes_random(data_str: str, tam: int) -> bytes:
    """
    Si data_str < tam: completa con bytes aleatorios.
    Si data_str > tam: trunca.
    Retorna bytes de longitud exacta tam.
    """
    b = data_str.encode("utf-8", errors="ignore")
    if len(b) < tam:
        b += get_random_bytes(tam - len(b))
    return b[:tam]

def ajustar_clave(alg: str, key_in: str) -> bytes:
    """
    Ajusta la clave según algoritmo:
      - DES:  8 bytes
      - AES: 32 bytes (AES-256)
      - 3DES: 24 bytes + paridad válida, evita claves débiles
    """
    if alg == "DES":
        return ajustar_bytes_random(key_in, 8)

    if alg == "AES":
        return ajustar_bytes_random(key_in, 32)

    base = ajustar_bytes_random(key_in, 24)
    try:
        base = TDES.adjust_key_parity(base)
    except AttributeError:
        pass

    for _ in range(32):
        try:
            DES3.new(base, DES3.MODE_ECB)  
            return base
        except ValueError:
            base = bytearray(base)
            base[-1] = get_random_bytes(1)[0]
            base = bytes(base)
            try:
                base = TDES.adjust_key_parity(base)
            except AttributeError:
                pass

    base = get_random_bytes(24)
    try:
        base = TDES.adjust_key_parity(base)
    except AttributeError:
        pass
    return base

def ajustar_iv(alg: str, iv_in: str) -> bytes:
    tam = 16 if alg == "AES" else 8
    return ajustar_bytes_random(iv_in, tam)

def bloque_size(alg: str) -> int:
    return 16 if alg == "AES" else 8

def cifrar_descifrar(alg: str, key: bytes, iv: bytes, texto: str):
    data = texto.encode("utf-8")
    bs = bloque_size(alg)
    data_padded = pad(data, bs)

    if alg == "DES":
        cipher = DES.new(key, DES.MODE_CBC, iv)
        decipher = DES.new(key, DES.MODE_CBC, iv)
    elif alg == "AES":
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decipher = AES.new(key, AES.MODE_CBC, iv)
    else:  # 3DES
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        decipher = DES3.new(key, DES3.MODE_CBC, iv)

    ct = cipher.encrypt(data_padded)
    pt = unpad(decipher.decrypt(ct), bs)
    return ct, pt

def main():
    print("=== CIFRADO SIMÉTRICO CBC ===")
    try:
        texto = input("Ingrese el texto a cifrar: ").strip()
    except KeyboardInterrupt:
        print("\nInterrumpido.")
        sys.exit(1)

    for alg in ["DES", "AES", "3DES"]:
        print_sep(alg)

        if alg == "DES":
            kbytes, ivbytes = 8, 8
        elif alg == "AES":
            kbytes, ivbytes = 32, 16
        else:
            kbytes, ivbytes = 24, 8

        try:
            key_in = input(f"Ingrese clave ({kbytes} bytes aprox): ")
            iv_in = input(f"Ingrese IV ({ivbytes} bytes aprox): ")
        except KeyboardInterrupt:
            print("\nInterrumpido.")
            sys.exit(1)

        key = ajustar_clave(alg, key_in)
        iv = ajustar_iv(alg, iv_in)

        print(f"Clave final usada ({len(key)} bytes): {key!r}")
        print(f"IV final usado    ({len(iv)} bytes): {iv!r}")

        try:
            ct, pt = cifrar_descifrar(alg, key, iv, texto)
        except Exception as e:
            print(f"[ERROR] {alg}: {e}")
            continue

        print(">> Texto cifrado (hex):", to_hex(ct))
        print(">> Texto cifrado (b64):", to_b64(ct))
        print(">> Texto descifrado   :", pt.decode('utf-8', errors='replace'))

    print_sep("Fin")

if __name__ == "__main__":
    main()
