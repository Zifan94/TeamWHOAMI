from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Hash import SHA, HMAC
import os

class EncryptionEngine():
	EK = None
	IV = None

	def __init__(self, EK, IV):
		self.EK = EK
		self.IV = IV

	def encrypt(self, Plaintext):
		encrypt_counter = Counter.new(128, initial_value = int.from_bytes(self.IV, byteorder='big'))
		AES_Factory = AES.new(self.EK, mode = AES.MODE_CTR, counter = encrypt_counter)
		new_Ciphertext = AES_Factory.encrypt(Plaintext)
		return new_Ciphertext




class DecryptionEngine():
	EK = None
	IV = None

	def __init__(self, EK, IV):
		self.EK = EK
		self.IV = IV

	def decrypt(self, Ciphertext):
		decrypt_counter = Counter.new(128, initial_value = int.from_bytes(self.IV, byteorder='big'))
		AES_Factory = AES.new(self.EK, mode = AES.MODE_CTR, counter = decrypt_counter)
		new_Plaintext = AES_Factory.decrypt(Ciphertext)
		return new_Plaintext




class MACEngine():
	MK = None

	def __init__(self, MK):
		self.MK = MK

	def calc_MAC(self, Ciphertext):
		new_MAC = HMAC.new(self.MK, Ciphertext, SHA)
		return new_MAC.digest()





class VerificationEngine():
	MK = None

	def __init__(self, MK):
		self.MK = MK

	def calc_MAC(self, Ciphertext):
		new_MAC = HMAC.new(self.MK, Ciphertext, SHA)
		return new_MAC.digest()
