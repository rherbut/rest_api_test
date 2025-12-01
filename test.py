import ssl
import requests
import tempfile
import base64
from cryptography.hazmat.primitives.serialization import pkcs12, Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.backends import default_backend
from config import P12_FILE, P12_PASSWORD, API_URL, API_USERNAME, API_PASSWORD

# ============================================================
# 1. Load and unpack the .p12 certificate
# ============================================================

with open(P12_FILE, "rb") as f:
    p12_data = f.read()

private_key, certificate, additional_certs = pkcs12.load_key_and_certificates(
    p12_data,
    P12_PASSWORD,
    backend=default_backend()
)

# ============================================================
# 2. Save certificate and private key as temporary PEM files
# ============================================================

cert_file = tempfile.NamedTemporaryFile(delete=False)
key_file = tempfile.NamedTemporaryFile(delete=False)

# Public certificate
cert_pem = certificate.public_bytes(Encoding.PEM)

# Include additional CA certificates if present in the .p12 bundle
if additional_certs:
    for ca in additional_certs:
        cert_pem += ca.public_bytes(Encoding.PEM)

# Private key
key_pem = private_key.private_bytes(
    Encoding.PEM,
    PrivateFormat.TraditionalOpenSSL,
    NoEncryption()
)

# Write to temporary files
cert_file.write(cert_pem)
key_file.write(key_pem)
cert_file.close()
key_file.close()

# ============================================================
# 3. Basic Authentication header
# ============================================================

basic_auth = base64.b64encode(
    f"{API_USERNAME}:{API_PASSWORD}".encode()
).decode()

headers = {
    "Accept": "application/json",
    "Authorization": f"Basic {basic_auth}",
}

# ============================================================
# 4. Prepare endpoint URL
# ============================================================

url = API_URL.rstrip("/") + "/v1/mimActions/schema"

# ============================================================
# 5. Send request (mTLS + BasicAuth)
# ============================================================

response = requests.get(
    url,
    headers=headers,
    cert=(cert_file.name, key_file.name),   # Client certificate + private key
    verify=False                            # Accept any server certificate (disable in production)
)

# ============================================================
# 6. Print response
# ============================================================

print("Status:", response.status_code)
print("Response:", response.text)
