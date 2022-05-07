####### PYPWD MANAGER BY GARANET.NET Version 1.0.8 ####
import os, sys, time, base64, pyAesCrypt
import pandas as pd

from zipfile import ZipFile 

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QTableWidgetItem, QFileDialog, QPushButton, QMessageBox
from PyQt5.QtCore import Qt

sys.path.append("./libs/")
from configfile import *
from language import *
#######################################################
class core:
    
    ### Write the Timeout Session
    def session():
        token = base64.urlsafe_b64encode(os.urandom(60))
        timestart = time.time()
        with open(sessiontmp,"w+") as f:
            f.write(str(token))
            f.write('\n')
            f.write(str(timestart))
        return(token,timestart)

    ### POPUP Timeout
    def dialog_exit():
        app = QtWidgets.QApplication([])
        infoBox = QtWidgets.QMessageBox()
        infoBox.setIcon(QtWidgets.QMessageBox.Warning)
        infoBox.setWindowTitle(OWEA)
        infoBox.setText(TMOT)
        infoBox.exec_()
        return False
    
    ### Check the Session
    def sessioncheck():
        try:
            with open(sessiontmp,"r") as f:
                session = f.read()
                result = [x.strip() for x in session.split('\n')]
                otoken = result[0]
                timestart =  result[1]
                core.timeout(timestart)
            return True
        except:            
            core.exit_now('','')
            return False
        return None

    ### Calculate the Session Timeout
    def timeout(timestart):
        timedone = time.time()
        elapsed = float(timedone) - float(timestart)
        if elapsed < secout:
            return None
        core.dialog_exit()
        self.close()
        core.exit_now('','')
        return None

    ### Close all system    
    def exit_now(self, timestart):
        try:
            df.drop(df.index, inplace=True)
        except:
            timestart=''
        try:
            os.remove(filetemp)
        except:
            self = ''
        try:
            os.remove(sessiontmp)
        except:
            pass
        try:
            os.system('exit')
        except:
            pass
        return(sys.exit(1))

    ### Simple DATE/TIME function
    def now():
        now = time.localtime()
        year = now[0]
        month = now[1]
        day = now[2]
        return (now,year,month,day)

    ### Restart the APP for the first login
    def restart():
        eapp = os.getcwd()
        os.execv(f'{eapp}/pypwd.py', sys.argv)
        sys.exit()
        return None    
    
    ### Find and check the Master Password
    def detemppwd(self):        
        datapwd = self.split("b'")[1]
        self = datapwd.split("'")[1]
        self = datapwd.encode(encoding)
        keysalt = base64.urlsafe_b64encode(key+key)
        cipher_suite = Fernet(keysalt)
        self = cipher_suite.decrypt(self)
        self = self.decode('utf-8')
        return self
    
    ### Decrypt password for keyfile
    def decrypt(self):
        bpass = bytes(self, encoding)
        kdf = PBKDF2HMAC(
             algorithm=hashes.SHA256(),
             length=23,
             salt=key,
             iterations=100000,
             backend=default_backend()
        )
        keyencrypt = base64.urlsafe_b64encode(kdf.derive(bpass))
        return keyencrypt.decode(encoding)
    
    ### Encrypt / Decrypt Master File
    def encryptMaster(self):
        bpass = bytes(self, encoding)
        keysalt = os.urandom(16)
        kdf = PBKDF2HMAC(
             algorithm=hashes.SHA256(),
             length=23,
             salt=keysalt,
             iterations=100000,
             backend=default_backend()
         )
        keyfile = base64.urlsafe_b64encode(kdf.derive(bpass))
        keyfile = keyfile.decode(encoding)
        with open("./libs/configfile.py","rt") as f:
            options = f.read()
            result = [x.strip() for x in options.split('\n')]
            key = result[3]
            key = [x.strip() for x in key.split(' = ')];
        ### SAVE SALT
        options = options.replace(str(key[1]),str(keysalt))
        with open("./libs/configfile.py","wt") as f:
            f.write(options)
        ### SALT PASSWORD
        keysalt = base64.urlsafe_b64encode(keysalt+keysalt)
        bpass = bytes(self, encoding)
        cipher_suite = Fernet(keysalt)
        encoded_text = cipher_suite.encrypt(bpass)
        return keyfile,encoded_text      
        
    ### Hashing Password
    def hash_password(self):
        keysalt = base64.urlsafe_b64encode(key+key)
        bpass = bytes(self, encoding)
        cipher_suite = Fernet(keysalt)
        return cipher_suite.encrypt(bpass)      

    ### Password Verification
    def verify_password(self, password):        
        keysalt = base64.urlsafe_b64encode(key+key)
        bpass = bytes(password, encoding)
        cipher_suite = Fernet(keysalt)
        datapwd = self.split("b'")[1]
        self = datapwd.split("'")[1]
        self = datapwd.encode(encoding)
        dtext = cipher_suite.decrypt(self)
        dtext = dtext.decode(encoding)
        return password == dtext
############################################################################################################