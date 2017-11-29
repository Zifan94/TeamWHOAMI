

class CertFactory:

    @staticmethod
    def getPrivateKeyForAddr(addr):
        #root = "/home/netsec/Desktop/Cert/"
        print("getting [private key] now","rb")
        if addr == "20174.1.636.300":
            with open("/home/netsec/Desktop/Cert/client-prikey")as fp:
                private_key_user = fp.read()
            return private_key_user
        if addr == "20174.1.636.200":
            with open("/home/netsec/Desktop/Cert/server-prikey")as fp:
                private_key_user = fp.read()
            return private_key_user
        return None

    @staticmethod
    def getCertsForAddr(addr):
        #root = "/home/netsec/Desktop/Cert/"
        chain = []
        print("getting [certification] now")
        if addr == "20174.1.636.300":
            with open("/home/netsec/Desktop/Cert/signed-client.cert", 'rb')as fo:
                chain.append(fo.read())
            with open("/home/netsec/Desktop/Cert/signed.cert", 'rb')as fi:
                chain.append(fi.read())
            return chain
        if addr == "20174.1.636.200":
            with open("/home/netsec/Desktop/Cert/signed-server.cert", 'rb')as fo:
                chain.append(fo.read())
            with open("/home/netsec/Desktop/Cert/signed.cert", 'rb')as fi:
                chain.append(fi.read())
            return chain
        return None

    @staticmethod
    def getRootCert():
        # Enter the location of the Private key as per the location of the
        # system
        with open("/home/netsec/Desktop/Cert/root.crt","rb")as fp:
            rootcert = fp.read()
        return rootcert
