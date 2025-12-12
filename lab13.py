########################################################################
# Program:
#    Lab 13: Create a cipher
# Author:
#    Br. Helfrich, Kyle Mueller
# Summary:
#    This program will be able to encrypt and decrypt text using a
#    cipher.
########################################################################

import cipher

#############################################################
# GET REPORT
# Generates the report for the selected cipher.
#############################################################
def get_report(cipher):
    # get the text
    plaintext = input("Please enter the text: ")
    if plaintext == "":
        plaintext = "I am just \"plain\" text ~ 12345."

    # get the password
    password = input("Please enter the password: ")
    if password == "":
        password = "P@55w0rd!"
        print(f"Default password: {password}") 

    encrypted = cipher.encrypt(plaintext, password)
    decrypted = cipher.decrypt(encrypted, password)

    print("==================================="
            "===================================\n"
            "Cipher Name:    "
            f"{cipher.get_cipher_name()}\n" \
            "Student Name:   "
            f"{cipher.get_author()}\n" \
            "==================================="
            "===================================\n"
            "Citation:\n"
            f"{cipher.get_cipher_citation()}\n"
            "==================================="
            "===================================\n"
            f"Plain text:    {plaintext}\n" \
            f"Cipher text:   {encrypted}\n" \
            f"Decipher text: {decrypted}\n" \
            "==================================="
            "===================================\n"
            "Pseudocode:\n"
            f"{cipher.get_pseudocode()}")


#####################################################################
# MAIN
# drives the UI
#####################################################################
def main():

    the_cipher = cipher.Cipher()

    get_report(the_cipher)  # generate the report


if __name__ == "__main__":
    main()
