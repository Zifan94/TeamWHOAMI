import os

class CertFactory:

    @staticmethod
    def getPrivateKeyForAddr(addr):
        root = os.path.dirname(os.path.abspath('CertFactory.py'))
        #root = "/home/netsec/Desktop/Cert/"
        print("getting [private key] now","rb")
        if addr == "20174.1.636.300":
            with open(root+"/netsec_fall2017/lab3_protocol/Cert/client-prikey")as fp:
                private_key_user = fp.read()
            return private_key_user
        if addr == "20174.1.636.200":
            with open(root+"/netsec_fall2017/lab3_protocol/Cert/server-prikey")as fp:
                private_key_user = fp.read()
            return private_key_user
        return None

    @staticmethod
    def getCertsForAddr(addr):
        root = os.path.dirname(os.path.abspath('CertFactory.py'))
        #root = "/home/netsec/Desktop/Cert/"
        chain = []
        print("getting [certification] now")
        if addr == "20174.1.636.300":
            with open(root+"/netsec_fall2017/lab3_protocol/Cert/signed-client.cert", 'rb')as fo:
                chain.append(fo.read())
            with open(root+"/netsec_fall2017/lab3_protocol/Cert/signed.cert", 'rb')as fi:
                chain.append(fi.read())
            return chain
        if addr == "20174.1.636.200":
            with open(root+"/netsec_fall2017/lab3_protocol/Cert/signed-server.cert", 'rb')as fo:
                chain.append(fo.read())
            with open(root+"/netsec_fall2017/lab3_protocol/Cert/signed.cert", 'rb')as fi:
                chain.append(fi.read())
            return chain
        return None

    @staticmethod
    def getRootCert():
        root = os.path.dirname(os.path.abspath('CertFactory.py'))
        # Enter the location of the Private key as per the location of the
        # system
        with open(root+"/netsec_fall2017/lab3_protocol/Cert/root.crt","rb")as fp:
            rootcert = fp.read()
        return rootcert
