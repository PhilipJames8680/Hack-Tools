import base64

def decode_rot(cipher_text, rotations):
    
    decoded = ""
    for char in cipher_text:
        if char.isalpha():
            shift = rotations % 26
            if char.islower():
                decoded += chr((ord(char) - shift - 97) % 26 + 97)
            elif char.isupper():
                decoded += chr((ord(char) - shift - 65) % 26 + 65)
        else:
            decoded += char
    return decoded

def decode_base64(encoded_text):
    
    try:
        return base64.b64decode(encoded_text).decode('utf-8')
    except Exception as e:
        return f"Error decoding Base64: {e}"

def decode_base32(encoded_text):
    
    try:
        return base64.b32decode(encoded_text).decode('utf-8')
    except Exception as e:
        return f"Error decoding Base32: {e}"


def decode_ascii(ascii_sequence):
    
    try:
        return ''.join(chr(int(num)) for num in ascii_sequence.split())
    except Exception as e:
        return f"Error decoding ASCII: {e}"

def decode_hex(hex_string):
    
    try:
        return bytes.fromhex(hex_string).decode('utf-8')
    except Exception as e:
        return f"Error decoding Hex: {e}"

def main():
    print("""
 _______   ____     ______   ___    _______   ____   .______      
|       \ |___ \   /      | / _ \  |       \ |___ \  |   _  \     
|  .--.  |  __) | |  ,----'| | | | |  .--.  |  __) | |  |_)  |    
|  |  |  | |__ <  |  |     | | | | |  |  |  | |__ <  |      /     
|  '--'  | ___) | |  `----.| |_| | |  '--'  | ___) | |  |\  \----.
|_______/ |____/   \______| \___/  |_______/ |____/  | _| `._____|
                                                                  
""")
    print("1. Decode ROT(x)")
    print("2. Decode Base64")
    print("3. Decode Base32")
    print("4. Decode ASCII to Text")
    print("5. Decode Hexadecimal to Text")
    print("6. Exit")

    while True:
        choice = input("\nEnter your choice : ")
        
        if choice == '1':
            cipher_text = input("Enter the ROT cipher text: ")
            while True:
                try:
                    x = int(input("Enter the rotation amount (x): "))
                    decoded_text = decode_rot(cipher_text, x)
                    print(f"Decoded Text (ROT-{x}): {decoded_text}")
                    repeat = input("Try a different rotation? (y/n): ").lower()
                    if repeat != 'y':
                        break
                except ValueError:
                    print("Please enter a valid number for rotation.")
        
        elif choice == '2':
            encoded_text = input("Enter Base64 encoded text: ")
            print("Decoded Text:", decode_base64(encoded_text))
        
        elif choice == '3':
            encoded_text = input("Enter Base32 encoded text: ")
            print("Decoded Text:", decode_base32(encoded_text))
        
        
        elif choice == '4':
            ascii_sequence = input("Enter ASCII values (space-separated): ")
            print("Decoded Text:", decode_ascii(ascii_sequence))
        
        elif choice == '5':
            hex_string = input("Enter Hexadecimal string: ")
            print("Decoded Text:", decode_hex(hex_string))
        
        elif choice == '6':
            print("Exiting Decoder Tool. Goodbye!")
            break
        
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
