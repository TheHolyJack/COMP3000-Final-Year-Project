import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from config import config
from classes import Logger
import json

cryptography_logger = Logger("Crypt-Module")

def retrieve_keys(MMSI):
    """
    Makes a POST request to the key server to retrieve public and private keys.
    :param MMSI: The ships MMSI
    :return: Nothing
    """
    keys = requests.post(f"http://{config['key_server']}/request-key/{MMSI}", data={"MMSI": str(MMSI)})
    return keys.json()

def verify_keys(private, public):
    """
    Used to verify the keyset requested before initialisation. This is to ensure
    that the keyset works, through signing a string and verifying the signature afterwards.
    :param private: The private key.
    :param public: The public key.
    :return: True if keys verified, false if not.
    """
    test_string =  b'Hello There'
    cryptography_logger.Log(f"Verifying =keys against string: '{test_string}'")

    sig = private.sign(
        test_string,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    cryptography_logger.Log(f"Signature for string '{test_string}' created: {sig}")

    try:
        public.verify(
            sig,
            test_string,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        cryptography_logger.Log("Signature Verified")
        return True
    except InvalidSignature:
        cryptography_logger.Log("Signature not verified")
        return False


def load_keys(MMSI):
    """
    Loads the private and public RSA keys that have been requested from the management server.
    Tests the keys using verify_keys before loading.
    :param MMSI: Ships MMSI
    :return: Private and Public PEM.
    """
    cryptography_logger.Log(f"Requesting Keys")
    keys = retrieve_keys(MMSI)
    cryptography_logger.Log(f"Loading Keys")
    private_pem, public_pem = bytes(keys['private'], 'utf-8'), bytes(keys['public'], 'utf-8')
    cryptography_logger.Log(f"Keys Aquired, Loading...")
    public_pem = serialization.load_pem_public_key(public_pem)
    private_pem = serialization.load_pem_private_key((private_pem), password=None)
    cryptography_logger.Log(f"Loaded public and private keys")


    if verify_keys(private_pem, public_pem):
        cryptography_logger.Log("Keys verified, returning to app")
        return private_pem, public_pem
    else:
        cryptography_logger.Log("Keys not verified, contact admin")
        return False

    return private_pem, public_pem


def sign_string(private_pem, data):
    """
    Used to sign the given string.
    :param private_pem: Private RSA PEM.
    :param data: Data to be signed.
    :return: Signed Data, Signature.
    """
    # data = bytes(data, 'utf-8')
    sig = private_pem.sign(
        bytes(data, 'utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("HERE: ", sig)
    return data, sig


def verify_data_sig(public, data, sig):
    """
    Verifies a signature for a public key.
    :param public: Public key to be used.
    :param data:  Data to be verified.
    :param sig: Signature to verify.
    :return: True if verified, false if not.
    """

    data = json.dumps(data)
    data = bytes(data, encoding='utf-8')
    # sig = bytes(sig, encoding='utf-8')
    try:
        public.verify(
            sig,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return True
    except InvalidSignature:
        return False

def retrive_public_keys():
    """
    Retrives public keys from management server.
    :return: Public Keys in json format.
    """
    data = requests.get(f"http://{config['key_server']}/request-keys/")

    return data.json()

def load_public_key(public):
    """
    Loads a public key and returns a PEM for the key.
    :param public: Public RSA Key.
    :return: Public RSA PEM.
    """
    public_pem = bytes(public, 'utf-8')
    public_pem = serialization.load_pem_public_key(public_pem)

    return public_pem

def retrieve_monthly_keys():
    r = requests.get(f'http://{personal_conf}/request-monthly-keys/')
    data = r.json()
    pub,priv = data['public'], data['private']

if __name__ == "__main__":
    cryptography_logger.Log("Crypt module imported")


