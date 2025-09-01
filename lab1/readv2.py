#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
from scapy.all import rdpcap, ICMP, Raw
import string

GREEN = "\033[92m"
RESET = "\033[0m"

def extract_cipher_from_pcap(pcap_path):
    """
    Reconstruye el string enviado en 2.2:
    - Un paquete ICMP Echo Request por carácter
    - ICMP Data: [0..7]=timestamp (tv_sec,tv_usec) ; [8]=carácter ; resto plantilla
    Devolvemos los caracteres ordenados por icmp.seq (coherente con tu emisor).
    """
    pkts = rdpcap(pcap_path)
    seq_chars = []
    for p in pkts:
        if ICMP in p and p[ICMP].type == 8 and Raw in p:
            data = bytes(p[Raw].load)
            if len(data) >= 9:
                ch = chr(data[8])
                seq = int(p[ICMP].seq)
                seq_chars.append((seq, ch))
    seq_chars.sort(key=lambda x: x[0])
    return "".join(ch for _, ch in seq_chars)

def caesar_decrypt(text, shift):
    """Desplaza solo letras minúsculas a-z hacia atrás 'shift' posiciones."""
    res = []
    for c in text:
        if 'a' <= c <= 'z':
            res.append(chr((ord(c) - ord('a') - shift) % 26 + ord('a')))
        else:
            res.append(c)
    return "".join(res)

def score_spanish(s):
    """
    Heurística simple para escoger la opción más probable:
    - bonus por palabras comunes en español
    - bonus por frecuencia de letras (e, a, o, s, n, r, l)
    """
    common = [" el ", " la ", " de ", " que ", " en ", " y ", " un ", " una ",
              " por ", " con ", " se ", " los ", " del ", " las "]
    score = 0
    ss = " " + s.lower() + " "
    for w in common:
        score += 5 * ss.count(w)
    for c in "easnorli":
        score += s.count(c)
    # penaliza caracteres raros
    for c in set(s):
        if c not in string.ascii_lowercase + " ":
            score -= 1
    return score

def main():
    if len(sys.argv) < 2:
        print("Uso: sudo python3 readv2.py <archivo.pcap|pcapng>")
        sys.exit(1)

    pcap_path = sys.argv[1]
    cipher = extract_cipher_from_pcap(pcap_path)

    # Imprime el texto crudo capturado (cifrado) como línea 0
    lines = []
    lines.append(("0", cipher))

    # Genera 1..25 corrimientos
    candidates = []
    for shift in range(1, 26):
        plain = caesar_decrypt(cipher, shift)
        candidates.append((shift, plain))

    # Escoge el mejor
    best_shift, _ = max(candidates, key=lambda t: score_spanish(t[1]))

    # Prepara salida numerada estilo tu captura
    for shift, text in candidates:
        idx = str(shift)
        if shift == best_shift:
            lines.append((idx, f"{GREEN}{text}{RESET}"))
        else:
            lines.append((idx, text))

    # Imprime
    for idx, text in lines:
        print(f"{idx} {text}")

if __name__ == "__main__":
    main()
