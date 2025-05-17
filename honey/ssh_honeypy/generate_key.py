import paramiko
import os

# Generate RSA key
key = paramiko.RSAKey.generate(bits=2048)

# Save to file
key_path = os.path.join('static', 'server.key')
key.write_private_key_file(key_path)

print(f"RSA key generated and saved to {key_path}")
