

class CertFactory:

    @staticmethod
    def getPrivateKeyForAddr():
        # Enter the location of the Private key as per the location of the
        # system
        with open("/home/elroy/prikey")as fp:
            private_key_user = fp.read()
        return private_key_user

    @staticmethod
    def getCertsForAddr():
        # Enter the location of the Private key as per the location of the
        # system
        with open("/home/elroy/keycsr")as fp:
            private_key_user = fp.read()
        return private_key_user

    @staticmethod
    def getPublicKeyForAddr():
        # Enter the location of the Private key as per the location of the
        # system
        with open("/home/elroy/pubkey")as fp:
            private_key_user = fp.read()
        return private_key_user

    @staticmethod
    def getRootCert():
        # Enter the location of the Private key as per the location of the
        # system
        with open("/sign/user1_private")as fp:
            private_key_user = fp.read()
        return private_key_user
