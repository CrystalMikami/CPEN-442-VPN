import hashlib

class Protocol:
    # Initializer (Called from app.py)
    # TODO: MODIFY ARGUMENTS AND LOGIC AS YOU SEEM FIT
    def __init__(self):
        # Keys
        self.keyShared = None
        self.keySession = None
        # Protocol variables (sender and reciever variables are questionable, no place for user to enter their
        # identity, maybe we don't need this, ask TA)
        self.sender = None
        self.reciever = None
        self.RA = None
        self.RB = None
        # Sending message variables
        self.numMsg = None
        self.MAC = None
        # Components needed for DH (random exponent (a), large prime (p), generator (g))
        self.DHExponent = None
        self.p = None
        self.g = None
        # Self (DHA, g^a mod p) and other party's (DHB, g^b mod p) Diffie Hellman values
        self.DHA = None
        self.DHB = None
        pass

    #Protocol functions

    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    # Initial message: "Alice (sender's name)", RA (generate a random number)
    # TODO: IMPLEMENT THE LOGIC (MODIFY THE INPUT ARGUMENTS AS YOU SEEM FIT)
    def GetProtocolInitiationMessage(self):
        # Remember to set self.RA and self.sender
        self.RA = randint(0, 2000000)
        return "PotatoProtocol1" + self.sender + self.RA


    # Checking if a received message is part of your protocol (called from app.py)
    # Yes if part of protocol, No if it's an encrypted message
    # Protocol messages can be of the form: 
    #       "Alice", RA
    #       E("Bob", RB, g^b mod p, K), H(K|RA)
    #       E("Alice", g^a mod p, K), H(K|RB)
    # Encrypted message is of the form:
    #       E("Alice/Bob", msg, msg#, KS), MAC
    # TODO: IMPLMENET THE LOGIC
    def IsMessagePartOfProtocol(self, message):
        # This will be hard because you're just getting the ciphertext which is just 
        # a bunch of random letters/numbers (on the bright side, you only need to check
        # if it's a protocol or an actual message, no need to care about any other types)
        # Possible ideas:
        # First message is not encrypted, could just check for letters/numbers
        # 2nd and 3rd messages, you can check the last few ___ bits (however long the hash is,
        # assuming that the hash is always the same length) to find the hash, then compute the hash
        # yourself and verify that it is right (this works because we know both K and RA/RB, and it
        # is VERY unlikely for a random ciphertext to just perfectly match the hash)
        # Everything else will just return false (regardless of if it really is an encrypted message or not)
        # NOTE: I think that because both parties will be using the same code, both users will think of themselves
        # as user A. Make sure not to confuse the usage of A and B variables (should always use A instead of B 
        # variables, or else the code will not work properly).
        return (message[0:14] == "PotatoProtocol")
        




    # Processing protocol message
    # Protocol messages can be of the form: 
    #       "Alice", RA
    #       E("Bob", RB, g^b mod p, K), H(K|RA)
    #       E("Alice", g^a mod p, K), H(K|RB)
    # TODO: IMPLMENET THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    def ProcessReceivedProtocolMessage(self, message):
        # This is where most of the protocol takes place. You will probably need to collaborate with others.
        # Work with Dylan to find out if his "IsMessagePartOfProtocol()" can help identify which message it is.
        #
        # If the first message is recieved, save as self.reciever and self.RB (This might seem weird but
        # the user will always think of themselves as user A, thus the other part is always B, this is needed
        # for the protocol to work properly), then return the second message (you will need to generate and save several
        # pieces of information to self.____, encrypt the message and compute the hash)
        # You could collaborate with Ying Qi for the encryption part (decide if you guys want to create two functions for
        # encryption or just borrow and modify his code)
        #
        # If the second or third message is recieved, you will need to decrypt the ciphertext and verify the hashes.
        # The ciphertext will be a bunch of random letters/numbers (may not always be the same length).
        # To split between the encrypted message and hash (assuming the hash is always the same size)
        # you can take the last ___ bits (however long the hash is) of the ciphertext.
        # Verify the hash by computing your own version and comparing (throw EXCEPTION if needed)
        # Decrypt the encrypted portion and update self.___ values with the information given. If the second message was 
        # recieved, return the third message (same process as if first message was recieved). For the third message, just
        # return "" and call setSessionKey().
        return ""

    # Setting the key for the current session
    # TODO: MODIFY AS YOU SEEM FIT
    def SetSessionKey(self):
        # Sets session key to (g^b mod p)^a mod p
        self.keySession = pow(self.DHB, self.DHExponent, mod = self.p)
        # Forget DH exponents
        self.DHExponent = None
        pass

    # Message sending functions

    # Encrypting messages
    # Encrypted message is of the form:
    #       E("Alice/Bob", msg, msg#, KS), MAC
    # TODO: IMPLEMENT ENCRYPTION WITH THE SESSION KEY (ALSO INCLUDE ANY NECESSARY INFO IN THE ENCRYPTED MESSAGE FOR INTEGRITY PROTECTION)
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def EncryptAndProtectMessage(self, plain_text):
        cipher_text = plain_text
        # Only for encrypting messages (not protocol)
        # Remember to set self.numMsg (and update it for each message)
        # Uses a MAC
        return cipher_text


    # Decrypting and verifying messages
    # Encrypted message is of the form:
    #       E("Alice/Bob", msg, msg#, KS), MAC
    # TODO: IMPLEMENT DECRYPTION AND INTEGRITY CHECK WITH THE SESSION KEY
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def DecryptAndVerifyMessage(self, cipher_text):
        plain_text = cipher_text
        # Only for decrypting and verifying messages
        # Remember to set self.numMsg (and update it for each message)
        # Uses a MAC
        return plain_text
