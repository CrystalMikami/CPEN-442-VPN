class Protocol:
    # Initializer (Called from app.py)
    # TODO: MODIFY ARGUMENTS AND LOGIC AS YOU SEEM FIT
    def __init__(self):
        self._key = None
        pass


    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    # TODO: IMPLEMENT THE LOGIC (MODIFY THE INPUT ARGUMENTS AS YOU SEEM FIT)
    def GetProtocolInitiationMessage(self):
        return ""


    # Checking if a received message is part of your protocol (called from app.py)
    # TODO: IMPLMENET THE LOGIC
    def IsMessagePartOfProtocol(self, message):
        return False


    # Processing protocol message
    # TODO: IMPLMENET THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    def ProcessReceivedProtocolMessage(self, message):
        pass


    # Setting the key for the current session
    # TODO: MODIFY AS YOU SEEM FIT
    def SetSessionKey(self, key):
        self._key = key
        pass


    from Crypto.Cipher import AES
    import hashlib
    import base64

    # Encrypting messages
    # Encrypted message is of the form:
    #       E("Alice/Bob", msg, msg#, KS), MAC
    # TODO: IMPLEMENT ENCRYPTION WITH THE SESSION KEY (ALSO INCLUDE ANY NECESSARY INFO IN THE ENCRYPTED MESSAGE FOR INTEGRITY PROTECTION)
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def EncryptAndProtectMessage(self, plain_text):
        cipher_text = plain_text
        # Only for encrypting messages (not protocol)
        # Remember to set self.numMsg (and update it for each message)
        # Uses a hash (SHA 256)

        # Adds "Message" padding to the message
        message = 'Message'
        message_to_be_encrypted = message + plain_text

        key = self.keySession

        # I assume that the nonce will be wither one of RA or RB
        # But I am not sure whether both instances of protocol have both RA and RB,
        # To make sure, when establishing the protocol, we did record both RA and RB, right?
        cipher = AES.new(key, AES.MODE_EAX, nonce=self.RA)

        ciphertext, tag = cipher.encrypt_and_digest(message_to_be_encrypted)
        hash_ciphertext = hashlib.sha256(ciphertext).hexdigest()

        self.numMsg = self.numMsg + 1
        return plain_text + hash_ciphertext


    # Encrypting messages
    # Encrypted message is of the form:
    #       E("Alice/Bob", msg, msg#, KS), MAC
    # TODO: IMPLEMENT ENCRYPTION WITH THE SESSION KEY (ALSO INCLUDE ANY NECESSARY INFO IN THE ENCRYPTED MESSAGE FOR INTEGRITY PROTECTION)
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def EncryptAndProtectMessage(self, plain_text):
        cipher_text = plain_text
        # Only for encrypting messages (not protocol)
        # Remember to set self.numMsg (and update it for each message)
        # Uses a hash (SHA 256)

        message_in_binary = plain_text.encode('utf-8')

        #self.keySession = b'Sixteen byte key'
        #self.RA = b'ra'
        key = self.keySession

        # I assume that the nonce will be wither one of RA or RB
        # But I am not sure whether both instances of protocol have both RA and RB,
        # To make sure, when establishing the protocol, we did record both RA and RB, right?
        cipher = AES.new(key, AES.MODE_EAX, nonce=self.RA)

        ciphertext, tag = cipher.encrypt_and_digest(message_in_binary) #ciphertext is binary
        string_ciphertext = b64encode(ciphertext).decode('utf-8')      #string_ciphertext is string
        print('string_ciphertext:' + string_ciphertext)
        hash_ciphertext = hashlib.sha256(ciphertext).hexdigest()       #hashed the binary of ciphertext (in binary)

        self.numMsg = self.numMsg + 1
        return 'Message' + string_ciphertext + hash_ciphertext

    # Decrypting and verifying messages
    # Encrypted message is of the form:
    #       E("Alice/Bob", msg, msg#, KS), MAC
    # TODO: IMPLEMENT DECRYPTION AND INTEGRITY CHECK WITH THE SESSION KEY
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def DecryptAndVerifyMessage(self, cipher_text):
        plain_text = cipher_text
        # Only for decrypting and verifying messages
        # Remember to set self.numMsg (and update it for each message)
        # Uses a hash

        total_length = len(cipher_text)
        hash = cipher_text[total_length - 64: total_length]
        ciphertext_without_hash = cipher_text[7: total_length - 64]
        print('here')

        cipher_binary = b64decode(ciphertext_without_hash)

        cipher = AES.new(self.keySession, AES.MODE_EAX, nonce=self.RA)
        plaintext = cipher.decrypt(cipher_binary)

        rehash = hashlib.sha256(cipher_binary).hexdigest()

        if hash.decode('utf-8') == rehash:
            self.numMsg = self.numMsg + 1
            return plaintext
        else:
            return plaintext
