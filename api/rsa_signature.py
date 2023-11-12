from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import base64

"""
This option receives as input a @password, and generates a pair of RSA keys
(public and private), and stores them in the database.
"""
def generate_rsa_key_pair(password, key_size=2048):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
    )

    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key_pem.decode(), public_key_pem.decode()

"""
This option receives as inputs any @file_to_sign_content, and @private_key_content.
Once the private key lock password has been verified, the program must
generate the digital signature of the file.
"""
def sign_file(file_to_sign, private_key_pem, password):
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=password.encode(),
        backend=default_backend()
    )

    signature = private_key.sign(
        file_to_sign,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    #Convert to base64
    signature = base64.b64encode(signature).decode()
    return signature

"""
This option receives as inputs any @original_file_content, @signature_content, and @public_key_content.
The program must verify that the signature corresponds to the original file.
"""
def verify_signature(original_file_content, signature_content, public_key_content):
    public_key = serialization.load_pem_public_key(
        public_key_content,
        backend=default_backend()
    )
    
    signature = base64.b64decode(signature_content)

    public_key.verify(
        signature,
        original_file_content,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

