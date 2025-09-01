import sys, time, os, struct
from scapy.all import IP, ICMP, Raw, send

def build_payload(ch: str) -> bytes:
    # Timestamp estilo ping: 8 bytes (sec + usec en big endian)
    now = time.time()
    sec  = int(now)
    usec = int((now - sec) * 1_000_000)
    ts_bytes = struct.pack("!II", sec, usec)

    # Carácter a enviar
    char_byte = bytes([ord(ch) & 0xFF])
    
    # 7 bytes de ceros 
    zeros = bytes([0] * 7)
    
    # Patrón fijo de 39 bytes
    tail = bytes(range(0x10, 0x38)) 
    
    # Combinamos todo
    payload = ts_bytes + char_byte + zeros + tail
    assert len(payload) == 56, f"Payload mal armado: {len(payload)} bytes"
    return payload

def main():
    if len(sys.argv) < 2:
        print('Uso: sudo python3 pingv4.py "mensaje_cifrado" [destino=1.1.1.1]')
        sys.exit(1)

    msg = sys.argv[1]
    dst = sys.argv[2] if len(sys.argv) >= 3 else "1.1.1.1"

    icmp_id = os.getpid() & 0xFFFF

    for seq, ch in enumerate(msg):
        payload = build_payload(ch)
        pkt = IP(dst=dst) / ICMP(type=8, code=0, id=icmp_id, seq=seq) / Raw(load=payload)
        send(pkt, verbose=1) 
        time.sleep(0.2)

if __name__ == "__main__":
    main()