# AesGcm-256
AES encryption/decryption in gcm mode and use PBKDF2 for create key


AES-GCM key:
  bit_length: The bit length of the key to generate. Must be 128, 192, or 256.
 
encrypt(nonce, data, associated_data):
  Encrypts and authenticates the data provided as well as authenticating the associated_data.
  The output of this can be passed directly to the decrypt method.
  
    *-nonce (bytes-like)
    *-data (bytes)
    *-associated_data (bytes)

decrypt(nonce, data, associated_data):
  Decrypts the data and authenticates the associated_data.
  If you called encrypt with associated_data you must pass the same associated_data in decrypt or the integrity check will fail.
  
    *-nonce (bytes-like)
    *-data (bytes)
    *-associated_data (bytes)
