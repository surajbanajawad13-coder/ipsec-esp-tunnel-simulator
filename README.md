# IPsec ESP Tunnel Mode Simulator

## Files
- esp_tunnel.py      core logic: IPv4 builder/parser, Security Association, ESP encapsulate/decapsulate
- app.py             Flask server exposing the logic as a small JSON API
- templates/index.html   browser frontend
- requirements.txt

## Run
    pip install -r requirements.txt
    python app.py
Open http://127.0.0.1:5000

To run only the command-line demo: `python esp_tunnel.py`

## Using the UI
1. Enter inner and gateway addresses plus a message, click "Encrypt and encapsulate".
2. See the packet layout (outer IP | ESP header | IV | encrypted inner packet | ICV).
3. Click "Decapsulate" to recover the original packet.
4. Click "Flip one bit" then Decapsulate: the ICV check fails.
5. Click Decapsulate twice on an untouched packet: replay is rejected.

## Do we need a database?
No. The Security Association lives in memory (a Python object). A database would only be needed
to persist SAs across restarts (that is project P24, the SAD).
