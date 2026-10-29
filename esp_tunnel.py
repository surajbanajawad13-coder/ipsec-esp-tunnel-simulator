"""
IPsec ESP Packet Simulation - TUNNEL MODE  (Project P19, BCS703)
-----------------------------------------------------------------
Takes a complete IPv4 packet (header + payload), encrypts it, and wraps it in:

   [ New outer IP header | ESP header | IV | Encrypted(inner IP packet + trailer) | ICV ]

Algorithms (classic ESP combination):
   Encryption     : AES-256-CBC
   Authentication : HMAC-SHA256 truncated to 96 bits (ICV)

Install dependency:  pip install cryptography
Run               :  python esp_tunnel.py
"""

import os
import struct
import socket
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ESP_PROTO = 50        # IP protocol number for ESP
IPIP_PROTO = 4        # "Next header" value meaning the payload is an IP packet (tunnel mode)
TCP_PROTO = 6
BLOCK = 16            # AES block size in bytes
ICV_LEN = 12          # 96-bit Integrity Check Value


# ----------------------------------------------------------------------
# 1. Helpers to build / parse a basic IPv4 packet
# ----------------------------------------------------------------------
def ip_checksum(header: bytes) -> int:
    """Standard 16-bit one's-complement Internet checksum."""
    if len(header) % 2:
        header += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(header) // 2), header))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def build_ipv4(src: str, dst: str, proto: int, payload: bytes,
               ttl: int = 64, ident: int = 0x1234) -> bytes:
    """Create a 20-byte IPv4 header (no options) followed by the payload."""
    ver_ihl = (4 << 4) | 5
    total_len = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", ver_ihl, 0, total_len, ident,
                      0x4000, ttl, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    chk = ip_checksum(hdr)
    hdr = hdr[:10] + struct.pack("!H", chk) + hdr[12:]
    return hdr + payload


def parse_ipv4(packet: bytes) -> dict:
    ver_ihl, _, total_len, ident, _, ttl, proto, chk, src, dst = \
        struct.unpack("!BBHHHBBH4s4s", packet[:20])
    ihl = (ver_ihl & 0x0F) * 4
    return {"version": ver_ihl >> 4, "ihl": ihl, "total_len": total_len,
            "ttl": ttl, "proto": proto, "checksum": chk,
            "src": socket.inet_ntoa(src), "dst": socket.inet_ntoa(dst),
            "payload": packet[ihl:total_len]}


def build_mock_tcp(sport: int, dport: int, data: bytes) -> bytes:
    """Mock TCP segment (20-byte header, checksum left 0 - good enough for simulation)."""
    hdr = struct.pack("!HHIIBBHHH", sport, dport, 1000, 0, 5 << 4, 0x18, 8192, 0, 0)
    return hdr + data


# ----------------------------------------------------------------------
# 2. Security Association (SA)
# ----------------------------------------------------------------------
class SecurityAssociation:
    def __init__(self, spi, tunnel_src, tunnel_dst):
        self.spi = spi
        self.tunnel_src = tunnel_src      # outer source  (security gateway 1)
        self.tunnel_dst = tunnel_dst      # outer dest    (security gateway 2)
        self.enc_key = os.urandom(32)     # AES-256 key
        self.auth_key = os.urandom(32)    # HMAC key
        self.seq = 0                      # sender's sequence counter
        self.highest_seen = 0             # receiver's anti-replay state
        self.seen = set()


# ----------------------------------------------------------------------
# 3. ESP encapsulation (sender side)
# ----------------------------------------------------------------------
def esp_encapsulate(inner_packet: bytes, sa: SecurityAssociation, verbose=True) -> bytes:
    # (a) Build ESP trailer: padding + pad length + next header.
    #     Padded length of (payload + padding + 2) must be a multiple of the block size.
    pad_len = (-(len(inner_packet) + 2)) % BLOCK
    padding = bytes(range(1, pad_len + 1))             # default ESP padding 1,2,3...
    plaintext = inner_packet + padding + bytes([pad_len, IPIP_PROTO])

    # (b) Encrypt with AES-CBC using a fresh random IV.
    iv = os.urandom(BLOCK)
    enc = Cipher(algorithms.AES(sa.enc_key), modes.CBC(iv)).encryptor()
    ciphertext = enc.update(plaintext) + enc.finalize()

    # (c) ESP header = SPI (32 bit) + Sequence number (32 bit).
    sa.seq += 1
    esp_header = struct.pack("!II", sa.spi, sa.seq)

    # (d) ICV = HMAC over (ESP header + IV + ciphertext), truncated to 96 bits.
    signed_part = esp_header + iv + ciphertext
    icv = hmac.new(sa.auth_key, signed_part, hashlib.sha256).digest()[:ICV_LEN]

    # (e) New outer IP header with protocol = 50 (ESP).
    outer = build_ipv4(sa.tunnel_src, sa.tunnel_dst, ESP_PROTO, signed_part + icv)

    if verbose:
        print(f"  [ENCAP] padding added   : {pad_len} bytes")
        print(f"  [ENCAP] SPI / Seq       : {sa.spi:#010x} / {sa.seq}")
        print(f"  [ENCAP] IV              : {iv.hex()}")
        print(f"  [ENCAP] ICV             : {icv.hex()}")
        print(f"  [ENCAP] size inner/outer: {len(inner_packet)} -> {len(outer)} bytes")
    return outer


# ----------------------------------------------------------------------
# 4. ESP decapsulation (receiver side)
# ----------------------------------------------------------------------
def esp_decapsulate(outer_packet: bytes, sa: SecurityAssociation, verbose=True) -> bytes:
    ip = parse_ipv4(outer_packet)
    if ip["proto"] != ESP_PROTO:
        raise ValueError("Not an ESP packet")
    body = ip["payload"]

    spi, seq = struct.unpack("!II", body[:8])
    if spi != sa.spi:
        raise ValueError("Unknown SPI - no matching Security Association")

    iv = body[8:8 + BLOCK]
    ciphertext = body[8 + BLOCK:-ICV_LEN]
    icv = body[-ICV_LEN:]

    # (a) Verify integrity FIRST (before decrypting anything).
    expected = hmac.new(sa.auth_key, body[:-ICV_LEN], hashlib.sha256).digest()[:ICV_LEN]
    if not hmac.compare_digest(icv, expected):
        raise ValueError("ICV mismatch - packet tampered, DROPPED")

    # (b) Anti-replay check.
    if seq in sa.seen or seq <= sa.highest_seen - 32:
        raise ValueError(f"Replay detected (seq {seq}) - packet DROPPED")
    sa.seen.add(seq)
    sa.highest_seen = max(sa.highest_seen, seq)

    # (c) Decrypt and strip trailer.
    dec = Cipher(algorithms.AES(sa.enc_key), modes.CBC(iv)).decryptor()
    plaintext = dec.update(ciphertext) + dec.finalize()
    pad_len, next_header = plaintext[-2], plaintext[-1]
    if next_header != IPIP_PROTO:
        raise ValueError("Next header is not IP-in-IP")
    inner = plaintext[:len(plaintext) - 2 - pad_len]

    if verbose:
        print(f"  [DECAP] ICV verified, seq {seq} accepted, padding removed: {pad_len} bytes")
    return inner


# ----------------------------------------------------------------------
# 5. Pretty printing + demo
# ----------------------------------------------------------------------
def show_ip(title, packet):
    p = parse_ipv4(packet)
    print(f"{title}: {p['src']} -> {p['dst']}  proto={p['proto']}  ttl={p['ttl']}  "
          f"len={p['total_len']}")


def hexdump(data: bytes, n=48):
    return data[:n].hex(" ") + (" ..." if len(data) > n else "")


def main():
    # Gateway A (192.0.2.1) <==== ESP tunnel ====> Gateway B (198.51.100.1)
    sa_out = SecurityAssociation(spi=0x1001, tunnel_src="192.0.2.1", tunnel_dst="198.51.100.1")
    # Receiver shares the same keys (in real life, set up by IKE).
    sa_in = SecurityAssociation(spi=0x1001, tunnel_src="192.0.2.1", tunnel_dst="198.51.100.1")
    sa_in.enc_key, sa_in.auth_key = sa_out.enc_key, sa_out.auth_key

    # Original host-to-host packet: 10.0.1.5 -> 10.0.2.9 (private networks behind gateways)
    tcp = build_mock_tcp(40000, 80, b"GET /secret HTTP/1.1\r\nHost: intranet\r\n\r\n")
    original = build_ipv4("10.0.1.5", "10.0.2.9", TCP_PROTO, tcp)

    print("=" * 70)
    print("STEP 1: Original IP packet")
    show_ip("  Inner", original)
    print("  Hex  :", hexdump(original))

    print("\nSTEP 2: Encapsulate (encrypt + add ESP + new outer IP header)")
    tunneled = esp_encapsulate(original, sa_out)
    show_ip("  Outer", tunneled)
    print("  Hex  :", hexdump(tunneled))
    print("  (Inner source/destination are now hidden inside ciphertext)")

    print("\nSTEP 3: Decapsulate at the other gateway")
    recovered = esp_decapsulate(tunneled, sa_in)
    show_ip("  Recovered", recovered)
    print("  Matches original:", recovered == original)

    print("\nSTEP 4: Attack tests")
    tampered = bytearray(tunneled)
    tampered[40] ^= 0x01                                   # flip one bit in ciphertext
    for name, pkt in (("Tampered packet", bytes(tampered)), ("Replayed packet", tunneled)):
        try:
            esp_decapsulate(pkt, sa_in, verbose=False)
            print(f"  {name}: accepted (BAD)")
        except ValueError as e:
            print(f"  {name}: rejected -> {e}")
    print("=" * 70)


if __name__ == "__main__":
    main()
