#ROOTADDR = "/home/netsec/Desktop/Cert/root.crt"
ROOTADDR = "/home/zifan/Cert/root.crt"
#ROOTADDR = "/home/elroy/Cert/root.crt"

class CertFactory:

    @staticmethod
    def getPrivateKeyForAddr(addr):
        #root = "/home/netsec/Desktop/Cert/"
        print("getting [private key] now","rb")
        with open(addr)as fp:
            private_key_user = fp.read()
        return private_key_user

    @staticmethod
    def getCertsForAddr(addr): #TODO according to Piazza
        #root = "/home/netsec/Desktop/Cert/"
        print("getting [certification] now")
        with open(addr, 'rb')as fp:
            cert = fp.read()
        return cert

    @staticmethod
    def getRootCert():
        # Enter the location of the Private key as per the location of the
        # system
        with open(ROOTADDR,"rb")as fp:
            rootcert = fp.read()
        return rootcert
