# Feistel Cipher with S-Box for Arbitrary-Length Text Encryption in Python

# S-Box: 4-bit to 4-bit substitution table (16 entries)
SBOX = [
    0xE, 0x4, 0xD, 0x1, 0x2, 0xF, 0xB, 0x8,
    0x3, 0xA, 0x6, 0xC, 0x5, 0x9, 0x0, 0x7
]

def generate_round_keys(master_key, num_rounds=8):
    """Generate round keys from a 64-bit master key."""
    keys = []
    for i in range(num_rounds):
        shift = (i * 7) % 64
        subkey = ((master_key >> shift) ^ (master_key << (64 - shift)) & 0xFFFFFFFFFFFFFFFF) & 0xFFFFFFFF
        keys.append(subkey)
    return keys

def sbox_substitution(value):
    """Apply S-Box substitution to a 4-bit value."""
    result = 0
    for i in range(8):
        shift = i * 4
        nibble = (value >> shift) & 0xF
        substituted = SBOX[nibble]
        result |= (substituted << shift)
    return result

def round_function(right, subkey):
    """Feistel round function with S-Box."""
    temp = right ^ subkey
    temp = sbox_substitution(temp)
    return temp

def feistel_encrypt(plaintext, master_key, num_rounds=8):
    """Encrypt a 64-bit plaintext using Feistel cipher with S-Box."""
    plaintext = plaintext & 0xFFFFFFFFFFFFFFFF
    left = (plaintext >> 32) & 0xFFFFFFFF
    right = plaintext & 0xFFFFFFFF
    keys = generate_round_keys(master_key, num_rounds)
    
    for i in range(num_rounds):
        temp = right
        right = left ^ round_function(right, keys[i])
        left = temp
    
    ciphertext = (left << 32) | right
    return ciphertext

def feistel_decrypt(ciphertext, master_key, num_rounds=8):
    """Decrypt a 64-bit ciphertext using Feistel cipher with S-Box."""
    ciphertext = ciphertext & 0xFFFFFFFFFFFFFFFF
    left = (ciphertext >> 32) & 0xFFFFFFFF
    right = ciphertext & 0xFFFFFFFF
    keys = generate_round_keys(master_key, num_rounds)
    
    for i in range(num_rounds - 1, -1, -1):
        temp = left
        left = right ^ round_function(left, keys[i])
        right = temp
    
    plaintext = (left << 32) | right
    return plaintext

def text_to_blocks(text):
    """Convert text to a list of 64-bit blocks, padding if necessary."""
    # Pad text to a multiple of 8 bytes with null bytes
    padded_length = ((len(text) + 7) // 8) * 8
    padded_text = text.ljust(padded_length, '\0')
    
    # Convert to blocks
    blocks = []
    for i in range(0, padded_length, 8):
        block = padded_text[i:i+8]
        block_int = int.from_bytes(block.encode('ascii', errors='ignore'), 'big')
        blocks.append(block_int)
    return blocks

def blocks_to_text(blocks):
    """Convert a list of 64-bit blocks to text."""
    text = ''
    for block in blocks:
        block_bytes = block.to_bytes(8, 'big')
        text += block_bytes.decode('ascii', errors='ignore').rstrip('\0')
    return text.rstrip('\0')

def encrypt_text(text, master_key):
    """Encrypt arbitrary-length text using Feistel cipher in ECB mode."""
    # Convert text to blocks
    blocks = text_to_blocks(text)
    # Encrypt each block
    encrypted_blocks = [feistel_encrypt(block, master_key) for block in blocks]
    # Combine into a single hex string
    return ''.join(hex(block)[2:].zfill(16) for block in encrypted_blocks)

def decrypt_text(ciphertext_hex, master_key):
    """Decrypt hex ciphertext to text using Feistel cipher in ECB mode."""
    # Split hex string into 16-char (64-bit) blocks
    block_size = 16
    if len(ciphertext_hex) % block_size != 0:
        raise ValueError("Invalid ciphertext length.")
    
    # Convert hex blocks to integers
    blocks = []
    for i in range(0, len(ciphertext_hex), block_size):
        block_hex = ciphertext_hex[i:i+block_size]
        block_int = int(block_hex, 16)
        blocks.append(block_int)
    
    # Decrypt each block
    decrypted_blocks = [feistel_decrypt(block, master_key) for block in blocks]
    # Convert back to text
    return blocks_to_text(decrypted_blocks)

# Example usage
if __name__ == "__main__":
    # Fixed 64-bit master key
    master_key = 0x133457799BBCDFF1
    # Example text (arbitrary length)
    plaintext = "This is a longer text that needs to be encrypted!"
    
    print(f"Original text: {plaintext}")
    
    # Encrypt
    ciphertext = encrypt_text(plaintext, master_key)
    print(f"Encrypted (hex): {ciphertext}")
    
    # Decrypt
    decrypted = decrypt_text(ciphertext, master_key)
    print(f"Decrypted text: {decrypted}")
    
    # Verify
    assert decrypted == plaintext, "Decryption failed!"
    print("Encryption and decryption successful!")