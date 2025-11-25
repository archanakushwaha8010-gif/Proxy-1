from flask import Flask, request, Response, jsonify
import requests
import threading
import socket
import socketserver
import time
from threading import Thread

app = Flask(__name__)

# Proxy credentials
PROXY_USER = "bbecjchp"
PROXY_PASS = "te3mfic28iaw" 
PROXY_PORT = 7030

class ProxyManager:
    def __init__(self):
        self.active_connections = 0
        self.max_connections = 50
    
    def check_auth(self, auth_header):
        """Check proxy authentication"""
        if not auth_header:
            return False
        
        try:
            import base64
            auth_type, credentials = auth_header.split(' ', 1)
            if auth_type.lower() == 'basic':
                decoded = base64.b64decode(credentials).decode('utf-8')
                username, password = decoded.split(':', 1)
                return username == PROXY_USER and password == PROXY_PASS
        except:
            pass
        return False

proxy_manager = ProxyManager()

@app.route('/')
def home():
    return f"""
    <h1>🔒 Authenticated Proxy Server</h1>
    <p><b>Proxy Format:</b> 142.111.48.253:{PROXY_PORT}:{PROXY_USER}:{PROXY_PASS}</p>
    <p><b>Status:</b> Active | Connections: {proxy_manager.active_connections}</p>
    <p><b>Usage:</b> curl -x http://{PROXY_USER}:{PROXY_PASS}@142.111.48.253:{PROXY_PORT} http://example.com</p>
    """

@app.route('/proxy/<path:url>')
def proxy_request(url):
    """HTTP Proxy endpoint"""
    # Check authentication
    auth_header = request.headers.get('Proxy-Authorization') or request.headers.get('Authorization')
    
    if not proxy_manager.check_auth(auth_header):
        return jsonify({"error": "Proxy authentication required"}), 407
    
    proxy_manager.active_connections += 1
    
    try:
        target_url = f"https://{url}" if not url.startswith(('http://', 'https://')) else url
        
        headers = {
            key: value for key, value in request.headers 
            if key.lower() not in ['host', 'proxy-authorization', 'proxy-connection']
        }
        
        response = requests.request(
            method=request.method,
            url=target_url,
            headers=headers,
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            stream=True,
            timeout=30
        )
        
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        response_headers = [
            (name, value) for name, value in response.raw.headers.items()
            if name.lower() not in excluded_headers
        ]
        
        return Response(response.content, response.status_code, response_headers)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        proxy_manager.active_connections -= 1

@app.route('/status')
def status():
    """Proxy status endpoint"""
    return jsonify({
        "status": "active",
        "format": f"142.111.48.253:{PROXY_PORT}:{PROXY_USER}:{PROXY_PASS}",
        "connections": proxy_manager.active_connections,
        "max_connections": proxy_manager.max_connections
    })

def start_socks_proxy():
    """SOCKS5 Proxy with authentication"""
    class Socks5Handler(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                # Authentication negotiation
                self.request.recv(1024)
                self.request.sendall(b'\x05\x02')  # Offer username/password auth
                
                # Auth details
                auth_data = self.request.recv(1024)
                if auth_data[0] != 1:  # Username/password subnegotiation
                    self.request.close()
                    return
                
                username_len = auth_data[1]
                username = auth_data[2:2+username_len].decode()
                password_len = auth_data[2+username_len]
                password = auth_data[3+username_len:3+username_len+password_len].decode()
                
                # Check credentials
                if username == PROXY_USER and password == PROXY_PASS:
                    self.request.sendall(b'\x05\x00')  # Auth success
                else:
                    self.request.sendall(b'\x05\x01')  # Auth failed
                    self.request.close()
                    return
                
                # Handle connection request
                request_data = self.request.recv(1024)
                if request_data[1] == 1:  # CONNECT
                    self.handle_connect(request_data)
                    
            except Exception as e:
                pass
        
        def handle_connect(self, data):
            try:
                addr_type = data[3]
                if addr_type == 1:  # IPv4
                    target_ip = socket.inet_ntoa(data[4:8])
                    target_port = int.from_bytes(data[8:10], 'big')
                    
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as target_socket:
                        target_socket.connect((target_ip, target_port))
                        self.request.sendall(b'\x05\x00\x00\x01' + socket.inet_aton(target_ip) + target_port.to_bytes(2, 'big'))
                        
                        # Data relay
                        self.relay_data(target_socket)
                else:
                    self.request.sendall(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')  # Addr type not supported
                    
            except Exception as e:
                self.request.sendall(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')  # General failure
        
        def relay_data(self, target_socket):
            while True:
                try:
                    rlist, _, _ = select.select([self.request, target_socket], [], [], 60)
                    
                    for sock in rlist:
                        if sock is self.request:
                            data = self.request.recv(4096)
                            if not data:
                                return
                            target_socket.sendall(data)
                        else:
                            data = target_socket.recv(4096)
                            if not data:
                                return
                            self.request.sendall(data)
                except:
                    break
    
    # Start SOCKS5 server in background thread
    socks_server = socketserver.ThreadingTCPServer(('0.0.0.0', PROXY_PORT), Socks5Handler)
    socks_thread = Thread(target=socks_server.serve_forever)
    socks_thread.daemon = True
    socks_thread.start()

if __name__ == '__main__':
    # Start SOCKS5 proxy
    start_socks_proxy()
    print(f"🚀 Proxy Server Started!")
    print(f"📍 Format: 142.111.48.253:{PROXY_PORT}:{PROXY_USER}:{PROXY_PASS}")
    print(f"🔒 Auth: {PROXY_USER}:{PROXY_PASS}")
    
    # Start HTTP proxy
    app.run(host='0.0.0.0', port=10000, debug=False)
