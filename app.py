import os
import json
import subprocess
from flask import Flask, render_template, request

app = Flask(__name__)

# Define o diretório atual de forma dinâmica para funcionar em qualquer clone do Git
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.path.join(BASE_DIR, 'state.json')

def init_state():
    if not os.path.exists(STATE_FILE):
        with open(STATE_FILE, 'w') as f:
            json.dump({"last_ip_octet": 20}, f)

def get_next_ip_octet():
    init_state()
    with open(STATE_FILE, 'r') as f:
        data = json.load(f)
    
    next_ip = data["last_ip_octet"] + 1
    data["last_ip_octet"] = next_ip
    
    with open(STATE_FILE, 'w') as f:
        json.dump(data, f)
        
    return next_ip

def generate_keys():
    privkey = subprocess.check_output("wg genkey", shell=True).decode("utf-8").strip()
    pubkey = subprocess.check_output(f"echo {privkey} | wg pubkey", shell=True).decode("utf-8").strip()
    return privkey, pubkey

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate', methods=['POST'])
def generate():
    ip_octet = get_next_ip_octet()
    privkey, pubkey = generate_keys()
    
    config = f"""[Interface]
PrivateKey = {privkey}
Address = 10.210.100.{ip_octet}/32
DNS = 10.210.10.251, 10.210.10.252, ebpos.br

[Peer]
PublicKey = XbffZQYAiOkcVVNfQlVkXW/VCQxeCleLtJqUiKlfhRU=
AllowedIPs = 10.210.10.0/24, 10.210.20.0/24, 10.210.30.0/24, 10.210.60.0/24, 10.210.99.0/24, 10.210.100.0/24
Endpoint = 177.126.97.49:51820
"""
    
    client_ip = f"10.210.100.{ip_octet}"
    return render_template('index.html', config=config, pubkey=pubkey, ip=client_ip)

if __name__ == '__main__':
    init_state()
    app.run(host='0.0.0.0', port=80)