from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.padding import OAEP
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption


def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def save_keys_to_file(private_key, public_key):
    with open("../../keys/private_key.pem", "wb") as private_file:
        private_file.write(
            private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption()
            )
        )
    with open("../../keys/public_key.pem", "wb") as public_file:
        public_file.write(
            public_key.public_bytes(
                encoding=Encoding.PEM,
                format=PublicFormat.SubjectPublicKeyInfo
            )
        )


def load_private_key():
    with open("../../keys/private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    return private_key


def load_public_key():
    with open("../../keys/public_key.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return public_key


def encrypt_text(public_key, text):
    encrypted_text = public_key.encrypt(
        text.encode("utf-8"),
        OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_text


def decrypt_text(private_key, encrypted_text):
    decrypted_text = private_key.decrypt(
        encrypted_text,
        OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_text.decode("utf-8")


def write_to_file(file_name, content):
    with open(file_name, "wb") as file:
        file.write(content)


def read_from_file(file_name):
    with open(file_name, "rb") as file:
        return file.read()


def main():
    private_key, public_key = generate_keys()
    save_keys_to_file(private_key, public_key)

    input_file = "encryption/input_text.txt"
    with open(input_file, "r") as file:
        original_text = file.read()

    public_key = load_public_key()
    encrypted_text = encrypt_text(public_key, original_text)

    encrypted_file = "encryption/encrypted_text.bin"
    write_to_file(encrypted_file, encrypted_text)
    print(f"Text encrypted and saved to {encrypted_file}")

    private_key = load_private_key()
    encrypted_content = read_from_file(encrypted_file)
    decrypted_text = decrypt_text(private_key, encrypted_content)

    decrypted_file = "encryption/decrypted_text.txt"
    with open(decrypted_file, "w") as file:
        file.write(decrypted_text)
    print(f"Text decrypted and saved to {decrypted_file}")


if __name__ == "__main__":
    main()
