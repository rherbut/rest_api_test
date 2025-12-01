import ssl
import requests
import tempfile
from cryptography.hazmat.primitives.serialization import pkcs12, Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.backends import default_backend
from config import P12_FILE, P12_PASSWORD, API_URL

# ============================================================
# 1. Wczytaj plik .p12
# ============================================================

with open(P12_FILE, "rb") as f:
    p12_data = f.read()

private_key, certificate, additional_certs = pkcs12.load_key_and_certificates(
    p12_data,
    P12_PASSWORD,
    backend=default_backend()
)

# ============================================================
# 2. Zapisz certyfikat + klucz do plików tymczasowych
# ============================================================

cert_file = tempfile.NamedTemporaryFile(delete=False)
key_file = tempfile.NamedTemporaryFile(delete=False)

# publiczny certyfikat
cert_pem = certificate.public_bytes(Encoding.PEM)

# dołącz certyfikaty CA, jeśli istnieją
if additional_certs:
    for ca in additional_certs:
        cert_pem += ca.public_bytes(Encoding.PEM)

# prywatny klucz
key_pem = private_key.private_bytes(
    Encoding.PEM,
    PrivateFormat.TraditionalOpenSSL,
    NoEncryption()
)

# zapisz fizycznie do plików
cert_file.write(cert_pem)
key_file.write(key_pem)
cert_file.close()
key_file.close()

# ============================================================
# 3. Endpoint REST API
# ============================================================

url = API_URL.rstrip('/') + "/v1/mimActions/schema"

# ============================================================
# 4. Wysyłanie żądania tylko z certyfikatem (mTLS)
# ============================================================

try:
    response = requests.get(
        url,
        verify=False,                         # jeśli serwer ma swój CA, tutaj podaj ścieżkę
        cert=(cert_file.name, key_file.name)  # cert klienta + klucz
    )

    print("Status:", response.status_code)
    print("Odpowiedź:", response.text)

except Exception as e:
    print("Błąd:", e)
