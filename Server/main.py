from cryptography.exceptions import InvalidSignature
from flask import Flask, render_template, request
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

global ships
ships = {}


"""
This basic distribution package is meant to demonstrate how a global authority would distribute and designate keys.


In a real setting, there would be validation based upon the retrieval of public and private keys, but as this is for 
demonstration purposes they are just allocated.

"""

def generate_keys(MMSI):
    """
    Generates keys and allocates them to the given MMSI.
    :param MMSI:
    :return: Private and public RSA PEM.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,
        backend=default_backend()
    )

    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    ships[str(MMSI)] = public_pem.decode('ascii')

    if (validate_keys(private_key, public_key) == True):
        return {"private": (private_pem.decode('ascii')), "public": (public_pem.decode('ascii'))}


def validate_keys(private, public):
    """
    Validates a private, public RSA keypair through signing and validating a string.
    :param private: Private RSA PEM.
    :param public: Public RSA PEM.
    :return:
    """
    testing_text = b'The correct message!'

    sig = private.sign(
        testing_text,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    print(f"SIG: {sig}")

    try:
        public.verify(
            sig,
            testing_text,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Signature Verified")

        return True
    except InvalidSignature:
        print("Signature not valid")
        return False


def generate_key_list():
    """
    Generates and returns a list of all the public keys.
    :return: Dict containing ship MMSI and relating RSA Public Key.
    """
    global ships
    keys = {}
    print(keys)
    for ship in ships.values():

        keys[ship['mmsi']] = ship['keys']['public']

    return keys




app = Flask(__name__)

@app.route('/request-keys/', methods=["GET", "POST"])
def request_keys():
    keys = generate_key_list()
    return keys

@app.route('/request-key/<mmsi>', methods=['GET', 'POST'])
def request_key(mmsi):
    global ships

    keys = generate_keys(mmsi)
    ship = {'mmsi': mmsi, 'keys': keys}
    ships[ship['mmsi']] = ship
    print(keys)
    print(ship)
    print(ships)
    return keys

# @app.route('/request-monthly-keys/')
# def request_monthly_keys():
#     global monthly_keys
#     return monthly_keys

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8080)
