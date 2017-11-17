

class CertFactory:

    @staticmethod
    def getPrivateKeyForAddr(file):
        root = "/home/elroy/Cert/"
        print("getting [private key] now","rb")
        with open(root+file)as fp:
            private_key_user = fp.read()
        return private_key_user

    @staticmethod
    def getCertsForAddr(file):
        root = "/home/elroy/Cert/"
        print("getting [certification] now")
        with open(root+file, 'rb')as fp:
            private_key_user = fp.read()
        return private_key_user

    @staticmethod
    def getRootCert():
        # Enter the location of the Private key as per the location of the
        # system
        with open("/home/elroy/Cert/root.crt","rb")as fp:
            private_key_user = fp.read()
        return private_key_user
