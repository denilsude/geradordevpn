import os
import json
import subprocess
from functools import wraps
from flask import Flask, render_template, request, session, redirect, url_for, Response

# Configura o Flask para servir arquivos estáticos a partir da pasta "public" que você criou
app = Flask(__name__, static_folder='public', static_url_path='/public')
app.secret_key = 'super_senha_secreta_wg_2026'

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.path.join(BASE_DIR, 'state.json')

# --- CONFIGURAÇÃO DE LOGIN ---
USUARIO_ADMIN = "admin"
SENHA_ADMIN = "senha123"

def check_auth(username, password):
    return username == USUARIO_ADMIN and password == SENHA_ADMIN

def authenticate():
    return Response(
    'Acesso restrito. Insira usuario e senha corretos.\n', 401,
    {'WWW-Authenticate': 'Basic realm="Acesso Restrito - Gerador VPN"'})

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated
# ------------------------------

def init_state():
    if not os.path.exists(STATE_FILE):
        with open(STATE_FILE, 'w') as f:
            json.dump({"last_ip_octet": 19, "freed_ips": []}, f)

def get_state():
    init_state()
    with open(STATE_FILE, 'r') as f:
        return json.load(f)

def save_state(data):
    with open(STATE_FILE, 'w') as f:
        json.dump(data, f)

def peek_next_ip_octet():
    data = get_state()
    if data.get("freed_ips"):
        return sorted(data["freed_ips"])[0]
    return data.get("last_ip_octet", 19) + 1

def get_next_ip_octet():
    data = get_state()
    
    if data.get("freed_ips"):
        freed = sorted(data["freed_ips"])
        next_ip = freed.pop(0)
        data["freed_ips"] = freed
    else:
        next_ip = data.get("last_ip_octet", 19) + 1
        data["last_ip_octet"] = next_ip
        
    save_state(data)
    return next_ip

def generate_keys():
    privkey = subprocess.check_output("wg genkey", shell=True).decode("utf-8").strip()
    pubkey = subprocess.check_output(f"echo {privkey} | wg pubkey", shell=True).decode("utf-8").strip()
    return privkey, pubkey

@app.route('/')
@requires_auth
def index():
    next_ip = peek_next_ip_octet()
    dados_gerados = session.pop('dados_gerados', None)
    
    # Resgata dados de quando um IP é liberado manualmente
    ip_liberado_msg = session.pop('ip_liberado_msg', None)
    ip_liberado_cmd = session.pop('ip_liberado_cmd', None)
    
    state = get_state()
    freed_ips = state.get("freed_ips", [])
    
    return render_template('index.html', 
                           next_ip=f"10.210.100.{next_ip}",
                           dados=dados_gerados,
                           freed_ips=freed_ips,
                           ip_liberado_msg=ip_liberado_msg,
                           ip_liberado_cmd=ip_liberado_cmd)

@app.route('/generate', methods=['POST'])
@requires_auth
def generate():
    vpn_name = request.form.get('vpn_name', 'SemNome').strip()
    vpn_name_safe = vpn_name.replace(" ", "_")
    
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
    
    mikrotik_cmd_add = f'/interface wireguard peers add interface="wireguard-server" public-key="{pubkey}" allowed-address="{client_ip}/32" comment="{vpn_name_safe}"'
    mikrotik_cmd_remove = f'/interface wireguard peers remove [find comment="{vpn_name_safe}"]'
    
    session['dados_gerados'] = {
        'config': config,
        'pubkey': pubkey,
        'ip': client_ip,
        'mikrotik_cmd': mikrotik_cmd_add,
        'mikrotik_cmd_remove': mikrotik_cmd_remove,
        'vpn_name': vpn_name_safe
    }
    
    return redirect(url_for('index'))

@app.route('/free_ip', methods=['POST'])
@requires_auth
def free_ip():
    ip_to_free = request.form.get('ip_octet', '').strip()
    if ip_to_free.isdigit():
        ip_num = int(ip_to_free)
        data = get_state()
        
        if ip_num not in data.get("freed_ips", []) and ip_num <= data.get("last_ip_octet", 19):
            data.setdefault("freed_ips", []).append(ip_num)
            save_state(data)
            
            # Gera a mensagem e o comando focado estritamente em apagar o IP no Mikrotik
            session['ip_liberado_msg'] = f'IP 10.210.100.{ip_num} colocado na fila de reuso!'
            session['ip_liberado_cmd'] = f'/interface wireguard peers remove [find allowed-address="10.210.100.{ip_num}/32"]'
            
    return redirect(url_for('index'))

@app.route('/reset', methods=['POST'])
@requires_auth
def reset_ips():
    save_state({"last_ip_octet": 19, "freed_ips": []})
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_state()
    app.run(host='0.0.0.0', port=80)