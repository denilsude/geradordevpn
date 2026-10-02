import os
import json
import subprocess
from functools import wraps
from flask import Flask, render_template, request, session, redirect, url_for, Response

app = Flask(__name__)
# Chave secreta obrigatória para usar sessões no Flask (pode manter essa ou alterar)
app.secret_key = 'super_senha_secreta_wg_2026'

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.path.join(BASE_DIR, 'state.json')

# --- CONFIGURAÇÃO DE LOGIN ---
USUARIO_ADMIN = "admin"
SENHA_ADMIN = "Ebpos@P@$$"

def check_auth(username, password):
    return username == USUARIO_ADMIN and password == SENHA_ADMIN

def authenticate():
    """Envia um erro 401 que aciona o popup de login nativo do navegador"""
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
            json.dump({"last_ip_octet": 22}, f)

def peek_next_ip_octet():
    init_state()
    with open(STATE_FILE, 'r') as f:
        data = json.load(f)
    return data["last_ip_octet"] + 1

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
@requires_auth  # Exige senha para acessar a página
def index():
    next_ip = peek_next_ip_octet()
    
    # Resgata os dados da última geração se existirem e limpa a sessão.
    # Isso evita que o IP pule caso o usuário aperte F5.
    dados_gerados = session.pop('dados_gerados', None)
    
    return render_template('index.html', 
                           next_ip=f"10.210.100.{next_ip}",
                           dados=dados_gerados)

@app.route('/generate', methods=['POST'])
@requires_auth  # Exige senha para gerar IP
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
    
    mikrotik_cmd = f'/interface wireguard peers add interface="wireguard-server" public-key="{pubkey}" allowed-address="{client_ip}/32" comment="{vpn_name}"'
    
    # Ao invés de renderizar direto, salvamos na sessão e redirecionamos (Post-Redirect-Get)
    session['dados_gerados'] = {
        'config': config,
        'pubkey': pubkey,
        'ip': client_ip,
        'mikrotik_cmd': mikrotik_cmd,
        'vpn_name': vpn_name
    }
    
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_state()
    app.run(host='0.0.0.0', port=80)