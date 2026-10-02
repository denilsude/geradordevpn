import os
import json
import subprocess
from flask import Flask, render_template, request

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.path.join(BASE_DIR, 'state.json')

def init_state():
    if not os.path.exists(STATE_FILE):
        with open(STATE_FILE, 'w') as f:
            # Como você mencionou que o último gerado foi o 22, a base será 22 para o próximo ser 23.
            json.dump({"last_ip_octet": 22}, f)

def peek_next_ip_octet():
    """Apenas visualiza qual será o próximo IP sem incrementar o contador."""
    init_state()
    with open(STATE_FILE, 'r') as f:
        data = json.load(f)
    return data["last_ip_octet"] + 1

def get_next_ip_octet():
    """Pega o próximo IP e salva o novo estado incrementado."""
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
    next_ip = peek_next_ip_octet()
    return render_template('index.html', next_ip=f"10.210.100.{next_ip}")

@app.route('/generate', methods=['POST'])
def generate():
    vpn_name = request.form.get('vpn_name', 'SemNome').strip()
    ip_octet = get_next_ip_octet()
    privkey, pubkey = generate_keys()
    
    client_ip = f"10.210.100.{ip_octet}"
    
    config = f"""[Interface]
PrivateKey = {privkey}
Address = {client_ip}/32
DNS = 10.210.10.251, 10.210.10.252, ebpos.br

[Peer]
PublicKey = XbffZQYAiOkcVVNfQlVkXW/VCQxeCleLtJqUiKlfhRU=
AllowedIPs = 10.210.10.0/24, 10.210.20.0/24, 10.210.30.0/24, 10.210.60.0/24, 10.210.99.0/24, 10.210.100.0/24
Endpoint = 177.126.97.49:51820
"""
    
    # Comando de terminal automatizado para o Mikrotik
    mikrotik_cmd = f'/interface wireguard peers add interface="wireguard-server" public-key="{pubkey}" allowed-address="{client_ip}/32" comment="{vpn_name}"'
    
    # Prepara o próximo IP para continuar exibindo no formulário
    next_ip_preview = peek_next_ip_octet()
    
    return render_template('index.html', 
                           config=config, 
                           pubkey=pubkey, 
                           ip=client_ip, 
                           mikrotik_cmd=mikrotik_cmd,
                           vpn_name=vpn_name,
                           next_ip=f"10.210.100.{next_ip_preview}")

if __name__ == '__main__':
    init_state()
    app.run(host='0.0.0.0', port=80)