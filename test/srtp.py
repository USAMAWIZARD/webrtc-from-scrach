
from Crypto.Util.number import bytes_to_long, long_to_bytes


  # IV = (k_s * 2 ^ 16) XOR(SSRC * 2 ^ 64) XOR(i * 2 ^ 16)
seskey = bytes_to_long(bytes.fromhex("F0F1F2F3F4F5F6F7F8F9FAFBFCFD0000"))
res = long_to_bytes( seskey * (2 ** 16))

print(res.hex())
