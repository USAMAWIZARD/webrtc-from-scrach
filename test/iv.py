
import struct
import binascii

def calculate_iv(ssrc, index, salt_key):
    # Convert salt key from hex string to bytes
    salt_bytes = binascii.unhexlify(salt_key)
    
    # Convert SSRC and index to integers
    ssrc = int(ssrc)
    index = int(index)
    
    # Convert SSRC and index to their shifted 128-bit equivalents
    term1 = int.from_bytes(salt_bytes, 'big') << 16
    term2 = ssrc << 64
    term3 = index << 16
    
    # Calculate the IV as a 128-bit XOR of the three terms
    iv = term1 ^ term2 ^ term3
    
    # Convert the IV back to bytes and return as hex
    return iv.to_bytes(16, 'big')

# Example usage
ssrc = 0
index = 2
salt_key = "f0f1f2f3f4f5f6f7f8f9fafbfcfd"

iv = calculate_iv(ssrc, index, salt_key)
print("IV:", binascii.hexlify(iv))

