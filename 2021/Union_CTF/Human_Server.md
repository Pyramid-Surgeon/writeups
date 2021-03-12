# Human Servers

Human servers was a crypto key exchange challenge. Bob and Allice are using eliptic curves to exchange a key, they then verify they both have the same key and then send the encrypted flag.

Fortunatly we are given the source code of this challenge. Taking a quick look at the key exchange something quickly jumps out.
```python
CURVE = secp256k1
ORDER = CURVE.q
G = CURVE.G

class EllipticCurveKeyExchange():
    def __init__(self):
        self.private = random.randint(0,ORDER)
        self.public = self.get_public_key()
        self.recieved = None
        self.nonce = None
        self.key = None

    def get_public_key(self):
        A = G * self.private
        return A

    def send_public(self):
        return print(json.dumps({"Px" : self.public.x, "Py" : self.public.y}))

    def receive_public(self, data):
        """
        Remember to include the nonce for ultra-secure key exchange!
        """
        Px = int(data["Px"])
        Py = int(data["Py"])
        self.recieved = Point(Px, Py, curve=secp256k1)
        self.nonce = int(data['nonce'])

    def get_shared_secret(self):
        """
        Generates the ultra secure secret with added nonce randomness
        """
        assert self.nonce.bit_length() > 64
        self.key = (self.recieved * self.private).x ^ self.nonce

    def check_fingerprint(self, h2: str):
        """
        If this is failing, remember that you must send the SAME
        nonce to both Alice and Bob for the shared secret to match
        """
        h1 = hashlib.sha256(long_to_bytes(self.key)).hexdigest()
        return h1 == h2

    def send_fingerprint(self):
        return hashlib.sha256(long_to_bytes(self.key)).hexdigest()
```
Generaly when approaching CTFs, especially with crypto CTFs, I like to see how the implementation provided differes from the norm. In this case the nonce stands out like a sore thumb
Nonces are used to prevent replay attacks (they are meant to be  used Not more than Once), there is no reason for it to be part of this key exchange.

So how exacly is this a problem? Well if we take a look at get_shared_secret we see it xors the eliptic curve point with the nonce. Because of this we can send our key to both Allice and Bob,
Then calculate which point on the curve they each have and send them two different nonces which will sync op the key.

This was our final exploit:
```python
from pwn import *
import json
from fastecdsa.curve import secp256k1
from fastecdsa.point import Point
from Crypto.Cipher import AES
from Crypto.Util.number import getPrime, long_to_bytes
import hashlib

CURVE = secp256k1
ORDER = CURVE.q
G = CURVE.G

class EllipticCurveKeyExchange():
    def __init__(self):
        self.private = random.randint(0,ORDER)
        self.public = self.get_public_key()
        self.recieved = None
        self.nonce = None
        self.key = None

    def get_public_key(self):
        A = G * self.private
        return A

    def send_public(self):
        return {"Px" : self.public.x, "Py" : self.public.y}

delta = EllipticCurveKeyExchange()

conn = remote('134.122.111.232', 54321)
conn.recvuntil(b'*                    Alice sends public key                    *\n')
for _ in range(2):
	conn.recvline()

# Setup alice's key
key_alice = json.loads(conn.recvline().decode('ascii'))
key_alice['nonce'] = "1" * 64
print("key_alice", key_alice)
conn.recvuntil(b"*              Please forward Alice's key to Bob               *\n")
for _ in range(2):
	conn.recvline()

delta.send_public()
key_delta = delta.send_public()
print(key_delta)
key_delta['nonce'] = "1" * 64
conn.send(json.dumps(key_delta))	# send my key to bob

conn.recvuntil(b'*                     Bob sends public key                     *\n')
for _ in range(2):
	conn.recvline()
key_bob = json.loads(conn.recvline().decode('ascii'))
aes_bob = (Point(key_bob['Px'], key_bob['Py'], curve=secp256k1) * delta.private).x ^ int("1" * 64)
aes_alice_nonce = (Point(key_alice['Px'], key_alice['Py'], curve=secp256k1) * delta.private).x ^ aes_bob
aes_alice = (Point(key_alice['Px'], key_alice['Py'], curve=secp256k1) * delta.private).x ^ aes_alice_nonce

conn.recvuntil(b"*              Please forward Bob's key to Alice               *\n")
for _ in range(2):
	conn.recvline()
key_delta['nonce'] = aes_alice_nonce
conn.send(json.dumps(key_delta))
assert aes_bob == aes_alice

conn.recvuntil(b'*              Alice sends encrypted flag to Bob               *\n')
for _ in range(2):
	conn.recvline()
encrypted = json.loads(conn.recvline().decode())
print(encrypted)
cipher = AES.new(hashlib.sha1(long_to_bytes(aes_alice)).digest()[:16], AES.MODE_CBC, bytearray.fromhex(encrypted['iv']))

plaintext = cipher.decrypt(bytearray.fromhex(encrypted['encrypted_flag']))
print(plaintext)
```
