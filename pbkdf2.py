import hashlib, binascii, os

def hash_password(password):
    """Hash a password for storing."""
    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('utf-8')
    pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), 
                                salt, 100000)
    pwdhash = binascii.hexlify(pwdhash)
    result = bytearray(salt + pwdhash)
    result.insert(0, 100)
    return result
def verify_password(stored_password, provided_password):
    """Verify a stored password against one provided by user"""
    salt = bytes(stored_password[1:65])
    stored_password = stored_password[65:]
    pwdhash = hashlib.pbkdf2_hmac('sha512', 
                                  provided_password.encode('utf-8'), 
                                  salt, 
                                  100000)
    pwdhash = binascii.hexlify(pwdhash)
    result = bytearray(pwdhash)
    return result == stored_password

stored_password=hash_password("123")
print(stored_password)
print(verify_password(stored_password, "123"))
print(verify_password(stored_password, "Abc"))