import hashlib
import random
import string
from Crypto.Cipher import AES

class Protocol:
    # Initializer (Called from app.py)
    # TODO: MODIFY ARGUMENTS AND LOGIC AS YOU SEEM FIT
    def __init__(self):
        # Keys
        self.secret = None
        self.keyShared = None
        self.keySession = None
        self.IV = 1

        # Protocol variables
        self.sender = None # The current user
        self.reciever = None # The user you are communicating with
        self.RA = None
        self.RB = None

        # Sending message variables
        self.numMsg = 0

        # Components needed for DH (random exponent (a), large prime (p), generator (g))
        self.DHExponent = None

        # Set p and g
        self.p = None
        self.g = None

        # Self (DHA, g^a mod p) and other party's (DHB, g^b mod p) Diffie Hellman values
        self.DHA = None
        self.DHB = None
        pass
    

    # Helper functions

    # Generates a random sting to serve as a nonce
    def RandomString(self, stringLength):
        choices = string.ascii_uppercase + string.digits
        return ''.join(random.choice(choices) for i in range(stringLength))


    # Hashes our key so we can get 256 bits
    def HashKey(self, thingToHash):
        # Hash the thingToHash using SHA-256
        key = hashlib.sha256(thingToHash.encode('utf-8')).hexdigest()
        return key


    #Protocol functions

    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    # Initial message: "PotatoProtocol1" + "Alice (sender's name)" + RA (generate a random number)
    # TODO: IMPLEMENT THE LOGIC (MODIFY THE INPUT ARGUMENTS AS YOU SEEM FIT)
    def GetProtocolInitiationMessage(self):
        # Generate RA
        self.RA = self.RandomString(8)
        # Calculate shared key
        self.keyShared = self.HashKey(self.secret)
        return "PotatoProtocol1" + self.sender + self.RA


    # Checking if a received message is part of your protocol (called from app.py)
    # Yes if part of protocol, No if it's an encrypted message
    # Protocol messages are prepended with "PotatoProtocol1/2/3"
    # Encrypted messages are prepended with "Message"
    # TODO: IMPLMENET THE LOGIC
    def IsMessagePartOfProtocol(self, message):
        # Check if PotatoProtocol is prepended
        return (message[0:14] == "PotatoProtocol")

    
    def EncryptAES(self, message, key):
        return AES.new(key, AES.MODE_CBC).encrypt(message)


    def DecryptAES(self, message, key):
        return AES.new(key, AES.MODE_CBC).decrypt(message)


    def PrepareProtocolMessage2(self):
        self.DHExponent = random.randint(0, 2000000)
        self.DHB = pow(self.g, self.DHExponent, mod = self.p)
        self.RB = self.RandomString(8)
        to_encrypt = self.sender + self.RB + self.DHB
        encrypted = self.EncryptAES(to_encrypt, self.keyShared)
        return "PotatoProtocol2" + encrypted + hashlib.sha256(to_encrypt.encode('utf-8')).hexdigest()

    def PrepareProtocolMessage3(self):
        self.DHA = pow(self.g, self.DHExponent, mod = self.p)
        to_encrypt = self.sender + self.DHA
        encrypted = self.EncryptAES(to_encrypt, self.keyShared)
        return "PotatoProtocol3" + encrypted + hashlib.sha256(to_encrypt.encode('utf-8')).hexdigest()

    # Processing protocol message
    # Protocol messages can be of the form: 
    #       "PotatoProtocol1", "A", RA
    #       "PotatoProtocol2", E("B", RB, g^b mod p, K), H("B", RB, g^b mod p)
    #       "PotatoProtocol3", E("A", g^a mod p, K), H("A", g^a mod p)
    # TODO: IMPLMENET THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    def ProcessReceivedProtocolMessage(self, message):
        # This is where most of the protocol takes place.
        #
        # If the first message is recieved, save the user (A/B) as self.reciever and RA as self.RA,
        # then return the second message. The second message will send self.sender, self.RB (that you need
        # to randomly generate and save) and self.DHB (g^b mod p that you need to calculate and save) that is
        # encrypted with self.keyShared.
        #
        # If the second message is recieved, decrypt and verify the message. Save the user
        # (A/B) as self.reciever, RB as self.RB, g^b mod p as self.DHB, then return the third message. The
        # third message will send self.sender, and self.DHA (g^a mod p that you need to calculate and save) that is
        # encrypted with self.keyShared. Call setSessionKey().
        #
        # If the third message is recieved, decrypt and verify the message. Return "" and
        # call setSessionKey().
        #
        # If the authentication fails at any point, throw an EXCEPTION

        if not (self.IsMessagePartOfProtocol(message)):
            raise Exception("Message is not part of protocol")

        if message[14] == "1":
            self.keyShared = self.HashKey(self.secret)
            self.reciever = message[15]
            self.RA = message[16:]
            return self.PrepareProtocolMessage2()
        elif message[14] == "2":
            decrypted = self.DecryptAES(message[15:-64], self.keyShared)
            my_hash = hashlib.sha256(decrypted.encode('utf-8')).hexdigest()
            if my_hash != message[-64:]:
                raise Exception("Authentication failed")
            self.reciever = decrypted[0]
            self.RB = decrypted[1:7]


    
        
    #Generating g^a mod p
    def GenerateDHA(self):
        self.DHA = pow(self.g, self.DHExponent, mod = self.p)


    # Setting the key for the current session
    # TODO: MODIFY AS YOU SEEM FIT
    def SetSessionKey(self, base):
        # Sets session key to H(g^ab mod p)
        DHVal = pow(base, self.DHExponent, mod = self.p)
        self.keySession = self.HashKey(self, DHVal)

        # Forget DH exponent
        self.DHExponent = None
        pass


    # Message functions

    # Encrypting messages
    # Encrypted message is of the form:
    #       "Message", E("A/B", msg, msg#, KS), H("A/B", msg, msg#)
    # TODO: IMPLEMENT ENCRYPTION WITH THE SESSION KEY (ALSO INCLUDE ANY NECESSARY INFO IN THE ENCRYPTED MESSAGE FOR INTEGRITY PROTECTION)
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def EncryptAndProtectMessage(self, plain_text):
        cipher_text = plain_text
        # Remember to set self.numMsg (and update it for each message)
        # Encrypt message with KS
        # Calculate the MAC
        return "Message" + cipher_text


    # Decrypting and verifying messages
    # Encrypted message is of the form:
    #       "Message", E("A/B", msg, msg#, KS), H("A/B", msg, msg#)
    # TODO: IMPLEMENT DECRYPTION AND INTEGRITY CHECK WITH THE SESSION KEY
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def DecryptAndVerifyMessage(self, cipher_text):
        plain_text = cipher_text
        # Remove "Message" from the front
        # Split into E() and H(MAC)
        # Verify MAC
        # Decrypt E()
        return plain_text
