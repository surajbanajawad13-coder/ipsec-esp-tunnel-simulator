"""
Flask backend for the ESP Tunnel Mode simulator (Project P19, BCS703).
All cryptography lives in esp_tunnel.py; this file only exposes it over HTTP.
Run:  python app.py   then open http://127.0.0.1:5000
"""
import os
from flask import Flask, request, jsonify, render_template
import esp_tunnel as E
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

app = Flask(__name__)


def new_sas():
    """Create the sender SA and a receiver SA that shares its keys (IKE is out of scope)."""
    out = E.SecurityAssociation(0x1001, "192.0.2.1", "198.51.100.1")
    inn = E.SecurityAssociation(0x1001, "192.0.2.1", "198.51.100.1")
    inn.enc_key, inn.auth_key = out.enc_key, out.auth_key
    return out, inn


sa_out, sa_in = new_sas()


def spaced(b: bytes) -> str:
    return b.hex(" ")


def describe(packet: bytes) -> dict:
    ip = E.parse_ipv4(packet)
    return {"src": ip["src"], "dst": ip["dst"], "proto": ip["proto"],
            "ttl": ip["ttl"], "length": ip["total_len"]}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/encapsulate", methods=["POST"])
def encapsulate():
    d = request.get_json(force=True)
    try:
        tcp = E.build_mock_tcp(40000, 80, d.get("payload", "").encode())
        inner = E.build_ipv4(d["inner_src"], d["inner_dst"], E.TCP_PROTO, tcp)
        sa_out.tunnel_src, sa_out.tunnel_dst = d["tunnel_src"], d["tunnel_dst"]
        outer = E.esp_encapsulate(inner, sa_out, verbose=False)
    except (OSError, KeyError, ValueError):
        return jsonify(ok=False, error="Enter valid IPv4 addresses, such as 10.0.1.5."), 400

    cuts = [("Outer IP header", outer[:20]), ("ESP header (SPI + Seq)", outer[20:28]),
            ("IV", outer[28:44]), ("Encrypted inner packet", outer[44:-12]),
            ("ICV", outer[-12:])]
    # Re-derive the intermediate values so the UI can explain each stage.
    iv, ct, icv = outer[28:44], outer[44:-12], outer[-12:]
    dec = Cipher(algorithms.AES(sa_out.enc_key), modes.CBC(iv)).decryptor()
    pt = dec.update(ct) + dec.finalize()
    return jsonify(ok=True, inner=describe(inner), inner_hex=spaced(inner),
                   outer=describe(outer), outer_hex=spaced(outer),
                   spi=hex(sa_out.spi), seq=sa_out.seq,
                   segments=[{"name": n, "len": len(b)} for n, b in cuts],
                   pad_len=pt[-2], next_header=pt[-1], padded_len=len(pt),
                   padding_hex=spaced(pt[len(inner):-2]), plain_hex=spaced(pt),
                   iv_hex=spaced(iv), cipher_hex=spaced(ct), icv_hex=spaced(icv),
                   message=d.get("payload", ""))


@app.route("/api/decapsulate", methods=["POST"])
def decapsulate():
    try:
        packet = bytes.fromhex(request.get_json(force=True)["hex"])
        inner = E.esp_decapsulate(packet, sa_in, verbose=False)
        text = E.parse_ipv4(inner)["payload"][20:].decode(errors="replace")
        return jsonify(ok=True, inner=describe(inner), payload=text)
    except ValueError as e:
        return jsonify(ok=False, error=str(e))
    except Exception:
        return jsonify(ok=False, error="Malformed packet - could not be parsed.")


@app.route("/api/reset", methods=["POST"])
def reset():
    global sa_out, sa_in
    sa_out, sa_in = new_sas()
    return jsonify(ok=True)


if __name__ == "__main__":
    app.run(debug=True, port=int(os.environ.get("PORT", 5000)))
