import os
import ecdsa
import hashlib
from segwit_addr import encode

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

# Witness version for P2WPKH is 0
witness_version = 0

# Encode to Bech32 address (human-readable part 'bc' for Bitcoin mainnet)
bech32_address = encode('bc', witness_version, hashed_public_key)
print("Bech32 (SegWit) Bitcoin Address:", bech32_address)
