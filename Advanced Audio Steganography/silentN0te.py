import wave
import numpy as np
import os
import hashlib
from typing import Tuple

def text_to_bits(text: str) -> str:
    # Convert text to binary string representation
    return ''.join(f"{ord(c):08b}" for c in text)

def bits_to_text(bits: str) -> str:
    # Convert binary string back to text
    bits = bits[:len(bits)//8*8]
    chars = [chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8)]
    return ''.join(chars)

def xor_data(text: str, key: bytes) -> str:
    # Apply XOR to text with a key
    key_len = len(key)
    return ''.join(chr(ord(c) ^ key[i % key_len]) for i, c in enumerate(text))

def generate_output_name(input_audio: str) -> str:
    # Generate output filename by appending 'steg'
    name, ext = os.path.splitext(input_audio)
    return f"{name}_steg{ext}"

def calculate_max_capacity(audio_file: str) -> Tuple[int, wave._wave_params]:
    # Calculate maximum storable bytes and return audio parameters
    with wave.open(audio_file, 'rb') as audio:
        params = audio.getparams()
        frames = audio.getnframes()
        channels = audio.getnchannels()
        samples = frames * channels
        max_bytes = samples // 8
        return max_bytes - 4, params  # 4 bytes reserved for header

def encode_audio_with_header(input_audio: str, secret: str, xor_key: bytes, output_audio: str) -> None:
    max_bytes, params = calculate_max_capacity(input_audio)

    if len(secret) > max_bytes:
        raise ValueError(f"Message too long. Max {max_bytes} bytes, got {len(secret)}")

    header = len(secret).to_bytes(4, byteorder='big')
    header_bits = text_to_bits(header.decode('latin-1'))  # 32 bits

    encrypted_secret = xor_data(secret, xor_key)
    secret_bits = text_to_bits(encrypted_secret)

    full_bits = header_bits + secret_bits

    with wave.open(input_audio, 'rb') as audio:
        frames = audio.readframes(params.nframes)

    samples = np.frombuffer(frames, dtype=np.int16).copy()

    for i, bit in enumerate(full_bits):
        samples[i] = (samples[i] & ~1) | int(bit)

    with wave.open(output_audio, 'wb') as out:
        out.setparams(params)
        out.writeframes(samples.tobytes())

    print(f"[+] Successfully encoded {len(secret)} bytes into '{output_audio}'")
    print(f"    Used hashed XOR key: {xor_key.hex()[:16]}...")
    print(f"    Original size: {os.path.getsize(input_audio)} bytes")
    print(f"    Stego size: {os.path.getsize(output_audio)} bytes")

def decode_audio_with_header(input_audio: str, xor_key: bytes) -> str:
    with wave.open(input_audio, 'rb') as audio:
        frames = audio.readframes(audio.getnframes())

    samples = np.frombuffer(frames, dtype=np.int16)

    header_bits = ''.join(str(samples[i] & 1) for i in range(32))
    header_bytes = bytes([int(header_bits[i:i+8], 2) for i in range(0, 32, 8)])
    message_length = int.from_bytes(header_bytes, byteorder='big')

    max_possible = (len(samples) - 32) // 8
    if message_length > max_possible:
        raise ValueError(f"Header claims {message_length} bytes but only {max_possible} possible")

    bits = ''.join(str(samples[i + 32] & 1) for i in range(message_length * 8))
    xor_encrypted = bits_to_text(bits)
    original_message = xor_data(xor_encrypted, xor_key)

    return original_message

def generate_key(password: str = None, salt: str = "stegosecure") -> bytes:
    """Generate multi-byte XOR key from hashed password"""
    if password is None:
        return bytes([0x55])  # default fallback
    salted = (password + salt).encode()
    return hashlib.sha256(salted).digest()

def main_menu():
    print("\n=== Audio Steganography Tool ===")
    print("1. Encode secret message")
    print("2. Decode secret message")
    print("3. Exit")

    while True:
        choice = input("\nSelect option (1-3): ").strip()

        if choice == '1':
            input_audio = input("Input audio file (.wav): ").strip()
            if not os.path.exists(input_audio):
                print("[!] File not found")
                continue

            secret = input("Secret message: ")
            password = input("Password (for encryption): ") or None
            xor_key = generate_key(password)

            output_audio = generate_output_name(input_audio)
            try:
                encode_audio_with_header(input_audio, secret, xor_key, output_audio)
            except ValueError as e:
                print(f"[!] Error: {e}")

        elif choice == '2':
            input_audio = input("Stego audio file (.wav): ").strip()
            if not os.path.exists(input_audio):
                print("[!] File not found")
                continue

            password = input("Password (must match encoding password): ") or None
            xor_key = generate_key(password)
            print(f"[*] Using XOR key hash: {xor_key.hex()[:16]}...")

            try:
                message = decode_audio_with_header(input_audio, xor_key)
                print("\n[+] Decoded message:")
                print(message)
            except Exception as e:
                print(f"[!] Decoding failed: {e}")

        elif choice == '3':
            print("Exiting...")
            break
        else:
            print("Invalid choice")

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\nOperation cancelled.")
