import streamlit as st
from PIL import Image
import numpy as np
from cryptography.fernet import Fernet
import qrcode
import io
import json
import os
import hashlib

# Configuration
USER_DATA_FILE = "users.json"
PEPPER = "secret-pepper-string"  # Add this to passwords before hashing

# Helper functions
def generate_keys():
    """Generate unique encryption/decryption keys for each user"""
    key = Fernet.generate_key()
    return key, key  # Symmetric encryption

def hash_password(password):
    """Secure password hashing with salt and pepper"""
    salt = os.urandom(32)
    return hashlib.pbkdf2_hmac(
        'sha256',
        (password + PEPPER).encode('utf-8'),
        salt,
        100000
    ).hex() + ":" + salt.hex()

def verify_password(stored_password, provided_password):
    """Verify hashed password"""
    hashed, salt = stored_password.split(":")
    new_hash = hashlib.pbkdf2_hmac(
        'sha256',
        (provided_password + PEPPER).encode('utf-8'),
        bytes.fromhex(salt),
        100000
    ).hex()
    return hashed == new_hash

def load_users():
    """Load user data from file"""
    if os.path.exists(USER_DATA_FILE):
        with open(USER_DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_users(users):
    """Save user data to file"""
    with open(USER_DATA_FILE, "w") as f:
        json.dump(users, f)

def aes_encrypt(message: str, key: bytes) -> str:
    """Encrypt message using AES"""
    fernet = Fernet(key)
    return fernet.encrypt(message.encode()).decode()

def aes_decrypt(encrypted_message: str, key: bytes) -> str:
    """Decrypt AES-encrypted message"""
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_message.encode()).decode()

def hide_text(image, text, key):
    """Hide encrypted text in image using LSB steganography"""
    encrypted_text = aes_encrypt(text, key)
    binary_text = ''.join(format(ord(c), '08b') for c in encrypted_text)
    binary_text += '1111111111111110'  # EOF marker
    
    image_array = np.array(image)
    flat = image_array.flatten()
    
    if len(binary_text) > len(flat):
        raise ValueError("Image too small to hold message")
    
    for i in range(len(binary_text)):
        flat[i] = (flat[i] & 0xFE) | int(binary_text[i])
    
    return Image.fromarray(flat.reshape(image_array.shape))

def reveal_text(image, key):
    """Extract hidden text from image"""
    image_array = np.array(image)
    flat = image_array.flatten()
    binary_str = ''.join(str(p & 1) for p in flat)
    eof = binary_str.find('1111111111111110')
    
    encrypted_text = ''.join(chr(int(binary_str[i:i+8], 2)) for i in range(0, eof, 8))
    return aes_decrypt(encrypted_text, key)

# Streamlit UI
st.title("Secure Image Text Encryption")

# Initialize session state
if 'user' not in st.session_state:
    st.session_state.user = None
if 'users' not in st.session_state:
    st.session_state.users = load_users()

# Authentication
if not st.session_state.user:
    st.header("Login / Sign Up")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Login"):
            if username in st.session_state.users:
                if verify_password(st.session_state.users[username]['password'], password):
                    st.session_state.user = username
                    st.rerun()
                else:
                    st.error("Incorrect password")
            else:
                st.error("User not found")
    
    with col2:
        if st.button("Sign Up"):
            if username and password:
                if username not in st.session_state.users:
                    enc_key, dec_key = generate_keys()
                    st.session_state.users[username] = {
                        'password': hash_password(password),
                        'enc_key': enc_key.decode(),
                        'dec_key': dec_key.decode()
                    }
                    save_users(st.session_state.users)
                    st.success("Account created! Please login")
                else:
                    st.error("Username already exists")
            else:
                st.error("Please enter username and password")
    st.stop()

# Main Application
st.header(f"Welcome {st.session_state.user}!")
user_data = st.session_state.users[st.session_state.user]

tab1, tab2, tab3 = st.tabs(["Encrypt", "Decrypt", "Keys"])

with tab1:
    st.subheader("Encrypt Message in Image")
    image_file = st.file_uploader("Upload Image", type=["png", "jpg", "jpeg"])
    message = st.text_area("Secret Message")
    
    if image_file and message:
        image = Image.open(image_file).convert("RGB")
        encrypted_image = hide_text(image, message, user_data['enc_key'].encode())
        
        buf = io.BytesIO()
        encrypted_image.save(buf, format="PNG")
        byte_im = buf.getvalue()
        
        st.download_button(
            label="Download Encrypted Image",
            data=byte_im,
            file_name="encrypted_image.png",
            mime="image/png"
        )
        st.image(encrypted_image, caption="Encrypted Image")

with tab2:
    st.subheader("Decrypt Message from Image")
    enc_image = st.file_uploader("Upload Encrypted Image", type=["png"])
    dec_key = st.text_input("Enter Decryption Key", type="password")
    
    if enc_image and dec_key:
        image = Image.open(enc_image)
        try:
            secret = reveal_text(image, dec_key.encode())
            st.success(f"Hidden message: {secret}")
        except Exception as e:
            st.error("Decryption failed: Invalid key or corrupted image")

with tab3:
    st.subheader("Your Keys")
    st.warning("Keep these keys secure! They cannot be recovered if lost.")
    st.code(f"Encryption Key: {user_data['enc_key']}")
    st.code(f"Decryption Key: {user_data['dec_key']}")
    
    # QR Code Generation
    qr = qrcode.make(user_data['dec_key'])
    buf = io.BytesIO()
    qr.save(buf)
    st.image(buf.getvalue(), caption="Decryption Key QR Code")
    st.info("Scan this QR code to share your decryption key securely")