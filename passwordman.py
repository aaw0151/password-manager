# This program was original created by Megan Luthra and Alexander Williams for a programming assignment for CSCE 3550 (Introduction to Computer Security) at the University of North Texas.
# The program was later edited by Alexander Williams.

# Information:
# Uses PBKDF2 (HMAC) for encrypting master password and AES for encryping each password in the password database.

import csv, os, sys, json, random, getpass
from Crypto.Hash import SHA256
from Cryptodome.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2


##
## CONSTANTS:
##

## Password Filename:
passwordFile = "passwords.pwm"

## Salts Filename (not encrypted):
saltFile = "salts.slt"

## Main Salt Value:
salt = "773r68765mUKUJgKBe9ey7Hp68TqXm2ASLzjbjWwr6XyqCF79xhwR24J9PmjCAB5"

## Password character set:
randomCharacters = 'ABCDEFGHIJLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@#$%!&-_+'

## Number of hash iterations (initialized to 1 million interations):
NUM_ITERATIONS = 10000

##The header of the file.
head = "   ___                                    _                                            \n" + "  / _ \__ _ ___ _____      _____  _ __ __| |   /\/\   __ _ _ __   __ _  __ _  ___ _ __ \n" + " / /_)/ _` / __/ __\ \ /\ / / _ \| '__/ _` |  /    \ / _` | '_ \ / _` |/ _` |/ _ \ '__|\n" + "/ ___/ (_| \__ \__ \\\\ V  V / (_) | | | (_| | / /\/\ \ (_| | | | | (_| | (_| |  __/ |   \n" + "\/    \__,_|___/___/ \_/\_/ \___/|_|  \__,_| \/    \/\__,_|_| |_|\__,_|\__, |\___|_|   \n" + "                                                                       |___/           " + "\n+------------------+\n|Alexander Williams|\n+------------------+\n"


#reference 1
def dictToBytes(dict):
        return json.dumps(dict).encode('utf-8')
def bytesToDict(dict):
        return json.loads(dict.decode('utf-8'))

#reference 2
def encrypt(dict, k):
        ##Defining the encryption scheme
        cipher = AES.new(k, AES.MODE_EAX)
        ##Encrypting the dictionary
        ciphertext, tag = cipher.encrypt_and_digest(dict)
	##Writing to password file
        with open(passwordFile, 'wb') as outfile:
                [outfile.write(x) for x in (cipher.nonce, tag, ciphertext)]

def decrypt(k):
        with open(passwordFile, 'rb') as infile:
                nonce, tag, ciphertext = [ infile.read(x) for x in (16, 16, -1) ]
                ##Define the encryption scheme here.
                cipher = AES.new(k, AES.MODE_EAX, nonce)
                ##Decrypt the ciphertext here.
                data = cipher.decrypt_and_verify(ciphertext, tag)

                return data

#function used to get an entry's salt from the salt file
def GetSalt(entry):
    saltForPass = '' #initializing salt for password
    with open(saltFile, 'r') as outfile: #opening salt file
        saltData = outfile.readlines() #reading all salts
        for singleSalt in saltData: #interating through all salts
            saltSplit = singleSalt.split(" ") #spliting salt into entry and salt
            if str(saltSplit[0]) == str(entry): #checking entry for the same entry in the salt file
                saltForPass = saltSplit[1].rstrip("\n") #setting salt
                return saltForPass


def Main():
        print("\n\n")

        if not os.path.isfile(passwordFile):
                mpw = str(getpass.getpass("Generating Passwords File\nEnter New Master Password: ")) #asking user for master password
        else:
                mpw = str(getpass.getpass("Enter Master Password: "))
        k = PBKDF2(mpw, salt, dkLen=32, count=NUM_ITERATIONS) # derive key from password
        mpw = '' #clearing master password from memory

        # check for password database file
        if not os.path.isfile(passwordFile):
                # create new passwords file
                print("No password database, creating....")
                newDict = dictToBytes({"": ""})
                encrypt(newDict, k)
                with open(saltFile, 'w+') as outfile:
                    outfile.write("")
                if len(sys.argv) != 2:
                    return

        # decrypt passwords file to dictionary
        try:
                print("Checking password...")
                pws = decrypt(k)
                pws = bytesToDict(pws)

        except Exception as e: #if wrong password
                print("Wrong password")
                return

        if len(sys.argv) != 2: # check for printing all stored passwords
                for entry in pws:
                    if entry != "":
                        print("entry   : %20s | pass: %s" % (str(entry), str(pws[entry]).replace(GetSalt(entry), "")))
                return
        entry = sys.argv[1]
        if entry in pws: #if entry exists
                #printing password
                print("entry   : " + str(entry))
                print("password: " + str(pws[entry]).replace(GetSalt(entry), ""))
        
        else: #no entry for that website
                print("No entry for " + str(entry) + ", creating new...")
                password = '' #initializing password string
                saltForPass = '' #intitializing salt string
                for pwchars in range(16): #generate random salt
                    saltForPass += random.choice(randomCharacters)
                with open(saltFile, 'a+') as outfile: #writing salt to salts file
                    outfile.write(str(entry) + " " + str(saltForPass) + "\n")
                password = str(getpass.getpass("Enter password (or press enter to generate a random 32 charcter password): ")) #asking for password
                if password == "": #if user wants to generate a password
                    for pwchars in range(32): #generate random password
                        password += random.choice(randomCharacters)
                    print("Generated new password for "+entry+": "+ password)
                pws[entry] = password + saltForPass #store salted random password
                password = '' #clearing password from memory
                encrypt(dictToBytes(pws), k) #encrypt password list
                pws = {} #clearing password dictionary from memory
        
        pws = {} #clearing password dictionary from memory


if __name__ == '__main__':
        print(str(head)) #printing header decal
        Main()
