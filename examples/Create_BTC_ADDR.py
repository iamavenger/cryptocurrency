import hashlib
import os
import ecdsa
import base58

# Generate a random 32-byte private key
private_key = os.urandom(32)
print("Private Key (hex):", private_key.hex())

# Create ECDSA signing key from private key using SECP256k1 curve
sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
vk = sk.verifying_key

# Get the public key bytes
vk_bytes = vk.to_string()

# Create compressed public key
if vk_bytes[-1] % 2 == 0:
    public_key_bytes = b'\x02' + vk_bytes[:32]
else:
    public_key_bytes = b'\x03' + vk_bytes[:32]

print("Compressed Public Key (hex):", public_key_bytes.hex())

# Hash the public key: SHA-256 then RIPEMD-160
sha256_pk = hashlib.sha256(public_key_bytes).digest()
ripemd160 = hashlib.new('ripemd160')
ripemd160.update(sha256_pk)
hashed_public_key = ripemd160.digest()
print("Public Key Hash (RIPEMD-160):", hashed_public_key.hex())

# Add network byte (0x00 for mainnet)
network_byte = b'\x00' + hashed_public_key

# Calculate checksum: double SHA-256, take first 4 bytes
checksum = hashlib.sha256(hashlib.sha256(network_byte).digest()).digest()[:4]

# Concatenate network byte + hashed public key + checksum
binary_address = network_byte + checksum

# Encode in Base58Check to get the final Bitcoin address
bitcoin_address = base58.b58encode(binary_address).decode()
print("Bitcoin Address:", bitcoin_address)
