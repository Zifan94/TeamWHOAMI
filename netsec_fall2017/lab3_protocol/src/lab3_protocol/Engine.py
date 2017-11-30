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
		encrypt_counter = Counter.new(128, initial_value = int.from_bytes(self.IV, byteorder='big'))
		self.AES_Factory = AES.new(self.EK, mode = AES.MODE_CTR, counter = encrypt_counter)

	def encrypt(self, Plaintext):
		new_Ciphertext = self.AES_Factory.encrypt(Plaintext)
		return new_Ciphertext




class DecryptionEngine():
	EK = None
	IV = None

	def __init__(self, EK, IV):
		self.EK = EK
		self.IV = IV
		decrypt_counter = Counter.new(128, initial_value = int.from_bytes(self.IV, byteorder='big'))
		self.AES_Factory = AES.new(self.EK, mode = AES.MODE_CTR, counter = decrypt_counter)

	def decrypt(self, Ciphertext):
		new_Plaintext = self.AES_Factory.decrypt(Ciphertext)
		return new_Plaintext




class MACEngine():
	MK = None

	def __init__(self, MK):
		self.MK = MK
		# self.new_MAC = HMAC.new(key = self.MK, msg = None, digestmod = SHA)

	def calc_MAC(self, Ciphertext):
		new_MAC = HMAC.new(self.MK, Ciphertext, SHA)
		new_MAC.update(Ciphertext)
		return new_MAC.digest()





class VerificationEngine():
	MK = None

	def __init__(self, MK):
		self.MK = MK
		# self.new_MAC = HMAC.new(key = self.MK, msg = None, digestmod = SHA)

	def calc_MAC(self, Ciphertext):
		new_MAC = HMAC.new(self.MK, Ciphertext, SHA)
		new_MAC.update(Ciphertext)
		return new_MAC.digest()
