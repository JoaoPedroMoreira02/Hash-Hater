import pyaes
import argparse
import base64
import hashlib

print(open('logo.txt', 'rt').read())

parse = argparse.ArgumentParser(
    description="Decrypt base64, MD5, SHA1, SHA256 and AES hash (Always know the hash type first :D)",
    epilog="Example: python3 decrypt_HASH.py -f/--file file.txt -m/--mode AES -k hereisthekey21")
parse.add_argument('-H', '--hash', metavar="", help="Encrypted hash string to decode")
parse.add_argument("-f", "--file", metavar="", type=str, help="Encrypted file with AES hash to decode")
parse.add_argument('-k', '--key', metavar="", type=str, help="Insert the AES Key value to decrypt")
parse.add_argument('-w', '--wordlist', metavar="", help="Wordlist to decrypt MD5, SHA1 and SHA256 hash")
parse.add_argument('-m', '--mode', metavar="", type=str, help="Hash mode ==> base64, MD5, SHA1, SHA256 and AES")
arg = parse.parse_args()

file_encrypted = arg.file
hash_value = arg.hash
key = arg.key
wordlist = arg.wordlist
mode = arg.mode

hash_list = ["base64", "MD5", "AES", "SHA1", "SHA256"]

def aes_decrypt(archive_AES):
    try:
        file = open(archive_AES, 'rb').read()
    except:
        print(f"[X] File not found with name {archive_AES}")
        quit()

    key_encode = key.encode('utf-8')
    
    aes = pyaes.AESModeOfOperationCTR(key_encode)
    decrypted = aes.decrypt(file)
    
    print()
    print("---" * 30)
    print(f"[+] Hash Decrypted => {decrypted.decode()}")
    print('---' * 30)


def base64_decrypt(hash_input):
    
    decrypted = base64.b64decode(hash_input)
    print(f"[+] Hash decoded => {decrypted.decode()}")
    print()
    

def MD5_decrypt(hash_input,pass_file):
    flag = 0

    pass_hash = hash_input
    try:
        pass_file = open(pass_file, "r")
    except:
        print(f"[X] Wordlist file not found with name {pass_file}")
        quit()

    for word in pass_file:

        enc_wrd = word.encode('utf-8')
        digest = hashlib.md5(enc_wrd.strip()).hexdigest()

        if digest == pass_hash:
            print(f"[+] Hash Found! => {word}")
            flag = 1
            break

    if flag == 0:
        print("The Hash is not in your wordlist.")


def sha256_decrypt(hash_input, pass_file):
    flag = 0

    pass_hash = hash_input
    try:
        pass_file = open(pass_file, "r")
    except:
        print(f"[X] Wordlist file not found with name {pass_file}")
        quit()

    for word in pass_file:

        enc_wrd = word.encode('utf-8')
        digest = hashlib.sha256(enc_wrd.strip()).hexdigest()

        if digest == pass_hash:
            print(f"[+] Hash Found! => {word}")
            flag = 1
            break

    if flag == 0:
        print("The Hash is not in your wordlist.")


def sha1_decrypt(hash_input, pass_file):
    flag = 0

    pass_hash = hash_input
    try:
        pass_file = open(pass_file, "r")
    except:
        print(f"[X] Wordlist file not found with name {pass_file}")
        quit()

    for word in pass_file:

        enc_wrd = word.encode('utf-8')
        digest = hashlib.sha1(enc_wrd.strip()).hexdigest()

        if digest == pass_hash:
            print(f"[+] Hash Found! => {word}")
            flag = 1
            break

    if flag == 0:
        print("The Hash is not in your wordlist.")
        quit()
    

if mode is None:
    print()
    print("[X] No hash mode selected")
    print("[please type -h to know how to use it]")
    print()
    print("Hash modes ==> base64, MD5, SHA1, AES")
    quit()
elif mode not in hash_list:
    print()
    print("[X] Unknown hash-type/unavailable")
    print("[Please type -h to see available hash modes]")
    quit()
elif mode != "AES" and mode != "base64" and wordlist is None:
    print()
    print("[X] No wordlist selected to decrypt")
    print("[please type -h to know how to use it]")
    quit()
elif mode != "MD5" and mode != "SHA256" and mode != "SHA1" and wordlist is not None:
    print()
    print("[X] Wordlist is for MD5, SHA1 and SHA256 hashes only")
    print("[please type -h to know how to use it]")
    quit()
elif mode == "AES" and key is None:
    print()
    print("[X] No key selected")
    print("[please type -h to know how to use it]")
    quit()
elif mode == "AES" and file_encrypted is None:
    print()
    print("[X] No file selected")
    print("[please type -h to know how to use it]")
    quit()
elif hash_value is None and mode != "AES":
    print()
    print("[X] Found no hash string to decrypt")
    print("[please type -h to know how to use it]")
    quit()
elif file_encrypted is not None and mode != "AES":
    print()
    print("[X] The file option is for files encrypted with AES hashes only")
    print("[please type -h to know how to use it]")
    quit()

if file_encrypted is not None and mode == "AES" and key is not None:
    aes_decrypt(file_encrypted)
elif hash_value is not None and mode == "base64":
    base64_decrypt(hash_value)
elif hash_value is not None and mode == "MD5" and wordlist is not None:
    MD5_decrypt(hash_value, wordlist)
elif hash_value is not None and mode == "SHA1" and wordlist is not None:
    sha1_decrypt(hash_value, wordlist)
elif hash_value is not None and mode == "SHA256" and wordlist is not None:
    sha256_decrypt(hash_value, wordlist)