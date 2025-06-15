#  EXPLICAÇÃO DOS USOS DE IA
# 
#  IA foi usada para adicionar comentários no código
#  Também foi usada para expandir o cósidgo para encriptar mensagens mais longas, já que o código original só suportava 16 bits
#  e não suportava texto
#  Toda a lógica inicial, de encriptação e de decriptação foi mantida e só foi expandida para suportar textos maiores



def generate_round_keys(master_key, num_rounds=4):
    """Generate simple round keys from a 32-bit master key."""
    keys = []
    for i in range(num_rounds):
        key = (master_key >> (i * 8)) & 0xFF  # Extract 8-bit subkeys
        keys.append(key)
    return keys

def feistel_encrypt(plaintext, master_key, num_rounds=4):
    """Encrypt 16-bit plaintext using a simple Feistel cipher."""
    plaintext = plaintext & 0xFFFF  # Ensure 16-bit input
    left = (plaintext >> 8) & 0xFF  # 8-bit left half
    right = plaintext & 0xFF       # 8-bit right half
    keys = generate_round_keys(master_key, num_rounds)
    
    for i in range(num_rounds):
        temp = right
        right = left ^ (right ^ keys[i])  # Simple XOR round function
        left = temp
    
    return (left << 8) | right

def feistel_decrypt(ciphertext, master_key, num_rounds=4):
    """Decrypt 16-bit ciphertext using a simple Feistel cipher."""
    ciphertext = ciphertext & 0xFFFF  # Ensure 16-bit input
    left = (ciphertext >> 8) & 0xFF  # 8-bit left half
    right = ciphertext & 0xFF       # 8-bit right half
    keys = generate_round_keys(master_key, num_rounds)
    
    for i in range(num_rounds - 1, -1, -1):
        temp = left
        left = right ^ (left ^ keys[i])  # Same XOR round function
        right = temp
    
    return (left << 8) | right

def text_to_blocks(text):
    """Convert text to 16-bit blocks, padding with null bytes."""
    padded_text = text + '\0' * (2 - len(text) % 2) if len(text) % 2 else text
    blocks = []
    for i in range(0, len(padded_text), 2):
        block = padded_text[i:i+2]
        block_int = int.from_bytes(block.encode('ascii'), 'big')
        blocks.append(block_int)
    return blocks

def blocks_to_text(blocks):
    """Convert 16-bit blocks to text."""
    text = ''
    for block in blocks:
        block_bytes = block.to_bytes(2, 'big')
        text += block_bytes.decode('ascii', errors='ignore').rstrip('\0')
    return text.rstrip('\0')

def encrypt_text(text, master_key):
    """Encrypt text using simple Feistel cipher."""
    blocks = text_to_blocks(text)
    encrypted_blocks = [feistel_encrypt(block, master_key) for block in blocks]
    return ''.join(hex(block)[2:].zfill(4) for block in encrypted_blocks)

def decrypt_text(ciphertext_hex, master_key):
    """Decrypt hex ciphertext to text."""
    block_size = 4
    if len(ciphertext_hex) % block_size != 0:
        raise ValueError("Invalid ciphertext length.")
    
    blocks = []
    for i in range(0, len(ciphertext_hex), block_size):
        block_int = int(ciphertext_hex[i:i+block_size], 16)
        blocks.append(block_int)
    
    decrypted_blocks = [feistel_decrypt(block, master_key) for block in blocks]
    return blocks_to_text(decrypted_blocks)

def main():
    """Main function to demonstrate Feistel cipher encryption and decryption."""
    master_key = 0x12345678  # 32-bit master key
    plaintext = "Hello!"
    
    print(f"Original text: {plaintext}")
    ciphertext = encrypt_text(plaintext, master_key)
    print(f"Encrypted (hex): {ciphertext}")
    decrypted = decrypt_text(ciphertext, master_key)
    print(f"Decrypted text: {decrypted}")
    assert decrypted == plaintext, "Decryption failed!"
    print("Encryption and decryption successful!")

main()