import os
import json
import subprocess
from datetime import timedelta
from functools import wraps
from flask import Flask, render_template, request, session, redirect, url_for

app = Flask(__name__, static_folder='public', static_url_path='/public')
app.secret_key = 'super_senha_secreta_wg_2026'

# Define o tempo de expiração da sessão para 1 hora de inatividade
app.permanent_session_lifetime = timedelta(hours=1)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.path.join(BASE_DIR, 'state.json')

# --- CONFIGURAÇÃO DE LOGIN ---
USUARIO_ADMIN = "admin"
SENHA_ADMIN = "senha123"

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated
# ------------------------------

def init_state():
    if not os.path.exists(STATE_FILE):
        with open(STATE_FILE, 'w') as f:
            json.dump({"last_ip_octet": 19, "freed_ips": [], "active_vpns": {}}, f)

def get_state():
    init_state()
    with open(STATE_FILE, 'r') as f:
        data = json.load(f)
        if "active_vpns" not in data:
            data["active_vpns"] = {}
        return data

def save_state(data):
    with open(STATE_FILE, 'w') as f:
        json.dump(data, f)

def peek_next_ip_octet():
    data = get_state()
    if data.get("freed_ips"):
        return sorted(data["freed_ips"])[0]
    return data.get("last_ip_octet", 19) + 1

def generate_keys():
    privkey = subprocess.check_output("wg genkey", shell=True).decode("utf-8").strip()
    pubkey = subprocess.check_output(f"echo {privkey} | wg pubkey", shell=True).decode("utf-8").strip()
    return privkey, pubkey

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == USUARIO_ADMIN and password == SENHA_ADMIN:
            session.permanent = True
            session['logged_in'] = True
            return redirect(url_for('index'))
        else:
            error = "Credenciais inválidas. Tente novamente."
    
    return render_template('index.html', show_login=True, error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@requires_auth
def index():
    next_ip = peek_next_ip_octet()
    dados_gerados = session.pop('dados_gerados', None)
    ip_liberado_msg = session.pop('ip_liberado_msg', None)
    ip_liberado_cmd = session.pop('ip_liberado_cmd', None)
    error_msg = session.pop('error_msg', None)
    
    state = get_state()
    freed_ips = state.get("freed_ips", [])
    
    return render_template('index.html', 
                           show_login=False,
                           next_ip=f"10.210.100.{next_ip}",
                           dados=dados_gerados,
                           freed_ips=freed_ips,
                           ip_liberado_msg=ip_liberado_msg,
                           ip_liberado_cmd=ip_liberado_cmd,
                           error_msg=error_msg)

@app.route('/generate', methods=['POST'])
@requires_auth
def generate():
    vpn_name_input = request.form.get('vpn_name', 'SemNome').strip()
    
    # PADRONIZAÇÃO DO NOME: Tudo maiúsculo, troca espaço por underline
    vpn_name_safe = vpn_name_input.replace(" ", "_").upper()
    
    # Garante o prefixo VPN-
    if not vpn_name_safe.startswith("VPN-"):
        vpn_name_safe = f"VPN-{vpn_name_safe}"
    
    state = get_state()
    active_vpns = state.get("active_vpns", {})
    
    # Validação: Impede nomes duplicados
    existing_names = [name.upper() for name in active_vpns.values()]
    if vpn_name_safe in existing_names:
        session['error_msg'] = f'ERRO: Já existe uma VPN ativa com o nome "{vpn_name_safe}".'
        return redirect(url_for('index'))
    
    if state.get("freed_ips"):
        freed = sorted(state["freed_ips"])
        ip_octet = freed.pop(0)
        state["freed_ips"] = freed
    else:
        ip_octet = state.get("last_ip_octet", 19) + 1
        state["last_ip_octet"] = ip_octet
        
    state["active_vpns"][str(ip_octet)] = vpn_name_safe
    save_state(state)
    
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
        state = get_state()
        
        if ip_num not in state.get("freed_ips", []) and ip_num <= state.get("last_ip_octet", 19):
            state.setdefault("freed_ips", []).append(ip_num)
            
            vpn_name_removed = state.get("active_vpns", {}).pop(str(ip_num), "Nome Desconhecido")
            save_state(state)
            
            session['ip_liberado_msg'] = f'IP 10.210.100.{ip_num} ({vpn_name_removed}) liberado e adicionado à fila!'
            session['ip_liberado_cmd'] = f'/interface wireguard peers remove [find allowed-address="10.210.100.{ip_num}/32"]'
            
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_state()
    app.run(host='0.0.0.0', port=80)