##############################################################################
# COMPONENT:
#    CIPHER01
# Author:
#    Johnathan I. Ruiz
# Summary:
#    Implement your cipher here. You can view 'example.py' to see the
#    completed Caesar Cipher example.
##############################################################################


##############################################################################
# CIPHER
##############################################################################
import struct

class Cipher:
    def __init__(self):
        self.key_parts = None

    def get_author(self):
        return "Johnathan I. Ruiz"

    def get_cipher_name(self):
        return "TEA"

    ##########################################################################
    # GET CIPHER CITATION
    # Returns the citation from which we learned about the cipher
    ##########################################################################
    def get_cipher_citation(self):
        s = "Wheeler, D. J.; Needham, R. M. (1994). TEA, a tiny encryption algorithm.\n"
        s += "Springer-Verlag, pp. 363-366. Retrieved from: \n"
        s += "https://link.springer.com/chapter/10.1007/3-540-60590-8_29"
        return s

    ##########################################################################
    # GET PSEUDOCODE
    # Returns the pseudocode as a string to be used by the caller
    ##########################################################################
    def get_pseudocode(self):
        pc = """
            encrypt(plaintext, password):
            key = derive_key(password)
            padded_plaintext = pad(plaintext)
            ciphertext = ""
            for each 8-byte block in padded_plaintext:
                v0, v1 = unpack(block)
                sum = 0
                delta = 0x9e3779b9
                for i in 0 to 31:
                sum += delta
                v0 += ((v1 << 4) + key[0]) ^ (v1 + sum) ^ ((v1 >> 5) + key[1])
                v1 += ((v0 << 4) + key[2]) ^ (v0 + sum) ^ ((v0 >> 5) + key[3])
                encrypted_block = pack(v0, v1)
                ciphertext += encrypted_block
            return ciphertext

            decrypt(ciphertext, password):
            key = derive_key(password)
            plaintext = ""
            for each 8-byte block in ciphertext:
                v0, v1 = unpack(block)
                delta = 0x9e3779b9
                sum = delta * 32
                for i in 0 to 31:
                v1 -= ((v0 << 4) + key[2]) ^ (v0 + sum) ^ ((v0 >> 5) + key[3])
                v0 -= ((v1 << 4) + key[0]) ^ (v1 + sum) ^ ((v1 >> 5) + key[1])
                sum -= delta
                decrypted_block = pack(v0, v1)
                plaintext += decrypted_block
            unpadded_plaintext = unpad(plaintext)
            return unpadded_plaintext
            """
        return pc

    def _derive_key(self, password):
        key = password.encode('utf-8')
        if len(key) < 16:
            key = key.ljust(16, b'\0')
        elif len(key) > 16:
            key = key[:16]
        self.key_parts = struct.unpack('<4I', key)

    ##########################################################################
    # ENCRYPT
    ##########################################################################
    def encrypt(self, plaintext, password):
        self._derive_key(password)
        
        # Pad plaintext to be a multiple of 8 bytes
        padding_len = 8 - (len(plaintext) % 8)
        plaintext += chr(padding_len) * padding_len
        
        ciphertext = b""
        
        for i in range(0, len(plaintext), 8):
            block = plaintext[i:i+8].encode('utf-8')
            v0, v1 = struct.unpack('<2I', block)
            
            sum_val = 0
            delta = 0x9e3779b9
            k = self.key_parts
            mask = 0xFFFFFFFF

            for _ in range(32):
                sum_val = (sum_val + delta) & mask
                val1 = ((v1 << 4) + k[0]) & mask
                val2 = (v1 + sum_val) & mask
                val3 = ((v1 >> 5) + k[1]) & mask
                v0 = (v0 + (val1 ^ val2 ^ val3)) & mask
                val1 = ((v0 << 4) + k[2]) & mask
                val2 = (v0 + sum_val) & mask
                val3 = ((v0 >> 5) + k[3]) & mask
                v1 = (v1 + (val1 ^ val2 ^ val3)) & mask

            ciphertext += struct.pack('<2I', v0, v1)

        return ciphertext.hex()

    ##########################################################################
    # DECRYPT
    ##########################################################################
    def decrypt(self, ciphertext, password):
        self._derive_key(password)
        
        ciphertext = bytes.fromhex(ciphertext)
        plaintext = b""

        for i in range(0, len(ciphertext), 8):
            block = ciphertext[i:i+8]
            c0, c1 = struct.unpack('<2I', block)

            delta = 0x9e3779b9
            sum_val = (delta * 32) & 0xFFFFFFFF
            k = self.key_parts
            mask = 0xFFFFFFFF

            for _ in range(32):
                val1 = ((c0 << 4) + k[2]) & mask
                val2 = (c0 + sum_val) & mask
                val3 = ((c0 >> 5) + k[3]) & mask
                c1 = (c1 - (val1 ^ val2 ^ val3)) & mask
                val1 = ((c1 << 4) + k[0]) & mask
                val2 = (c1 + sum_val) & mask
                val3 = ((c1 >> 5) + k[1]) & mask
                c0 = (c0 - (val1 ^ val2 ^ val3)) & mask
                sum_val = (sum_val - delta) & mask
            
            plaintext += struct.pack('<2I', c0, c1)

        padding_len = plaintext[-1]
        return plaintext[:-padding_len].decode('utf-8')
