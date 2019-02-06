from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import uuid
from pyDH import *
import os
import sys

class crypto:
    def __init__(self):
        self.backend = default_backend()

    #For creating RSA key pair
    def rsa_key_pair(self):
        private_key = rsa.generate_private_key(public_exponent=65537,
                                           key_size=2048,backend=self.backend)
        public_key = private_key.public_key()
        return public_key, private_key



    #For loading RSA keys for usage created in program
    def private_key_load(self, private_key_pem):
        private_pem = private_key_pem.private_bytes(encoding=serialization.Encoding.PEM,
                                                   format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                   encryption_algorithm=serialization.NoEncryption())
        return private_pem

    def public_key_load(self, public_key_pem):
        public_pem = public_key_pem.public_bytes(encoding=serialization.Encoding.PEM,
                                                 format=serialization.PublicFormat.SubjectPublicKeyInfo)
        return public_pem



    def key_conversion_bytes(self, public_key):
        return bytes(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                             format=serialization.PublicFormat.SubjectPublicKeyInfo))


    #Need to pass peer public key for key generation
    def diffie_hellman(self, peer_public_key):

        parameters = dh.generate_parameters(generator=5, key_size=2048,backend=default_backend())

        # A new private key for each exchange
        private_key = parameters.generate_private_key()
        #Pass the public of the peer
        shared_key = private_key.exchange(peer_public_key)

        derived_key = HKDF(algorithm=hashes.SHA256(),length=32,salt=None,
                           info=b'handshake data',backend=default_backend()).derive(shared_key)
        return derived_key

    def dh(self,peer_public_key):
        d1 = pyDH.DiffieHellman()
        d2 = pyDH.DiffieHellman()
        d1_pubkey = d1.gen_public_key()
        print d1_pubkey
        d2_pubkey = d2.gen_public_key()
        d1_sharedkey = d1.gen_shared_key(d2_pubkey)
        d2_sharedkey = d2.gen_shared_key(d1_pubkey)







    # Encrypt the message using the public key of the destination
    def rsa_encryption(self,public_key,message):
        ciphertext = public_key.encrypt(message,padding.OAEP(mgf = padding.MGF1(algorithm=hashes.SHA256()),
                                                             algorithm = hashes.SHA256(),label = None))
        return ciphertext

    # Decrypt the message using the private key of the receiver
    def rsa_decryption(self,private_key,ciphertext):
        plaintext = private_key.decrypt(ciphertext,padding.OAEP(mgf = padding.MGF1(algorithm=hashes.SHA256()),
                                                                algorithm = hashes.SHA256(),label = None))
        return plaintext


    # AES Symmetric encryption
    def symmetric_encryption(self,key,iv,payload):
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=self.backend) #specifying AES algorithm using GCM mode of operation
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(payload) + encryptor.finalize()
        return encryptor.tag, ciphertext


    # AES Symmetric decryption
    def symmetric_decryption(self, key, iv, ciphertext, tag):
        decryptor = Cipher(algorithms.AES(key),modes.GCM(iv, tag),backend=default_backend()).decryptor()
        #decryptor.authenticate_additional_data(ad)
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext


    #function to serialize private key on file
    def private_key(self,key_file):
     try:
           private_key_serial = serialization.load_pem_private_key(key_file.read(),password=None, backend=default_backend())


     except:
                   print "Key format not supported,(My developer is lazy)"
                   print "Supported key format: PEM"
                   sys.exit(1)

     return private_key_serial


    #function to serialize public key on file
    def public_key(self,key_file):

         public_key_serial = serialization.load_pem_public_key(key_file.read(), backend=default_backend())

         return public_key_serial


    def serialize_received_key(self,key_file):

        client_public_key=serialization.load_pem_public_key(key_file, backend=self.backend)

        return client_public_key



    def sign(self,private_key_sender,message): #pass the private key of the sender
        signature = private_key_sender.sign(message,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                                       salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())

        return signature

    #Pass the public key and signature of the sender
    #  Check if the signature tag is required
    def verify(self,public_key_sender,signature,message):
        public_key_sender.verify(signature,message,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                             salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())



    def key_derivation(self,password,salt):
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=100000,backend=self.backend)
        key = kdf.derive(password)
        return key

    def hash(self,message):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(message)
        digest.finalize()
        return digest



    def nonce_check(self,nonce):
         non=file("nonce",'r+b')
         nonce =nonce+'\n'
         if nonce not in non.readlines():
            non.write(nonce+'\n')

            return 1

         else:
            return 0


    def create_nonce(self):
        return str(uuid.uuid4().hex)

