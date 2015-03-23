__author__ = 'jinksPadlock'
from passlib import hash


def test_password(crypt_password, is_rainbowed, alg):
    # STUB: is_rainbowed  == TRUE could be used to check against a pre-hashed dictionary.
    if is_rainbowed is False:
        if alg == 'crypt':
            salt = crypt_password[0:2]
            dict_file = open('dictionary.txt', 'r')
            for word in dict_file.readlines():
                    word = word.strip('\n')
                    crypt_word = hash.des_crypt.encrypt(word, salt=salt)
                    if crypt_word == crypt_password:
                        print("[+] Found Password: " + word)
                        return
        if alg == 'md5':
                salt = crypt_password.split("$")[2]
                digest = crypt_password.split("$")[3]
                dict_file = open('dictionary.txt', 'r')
                for word in dict_file.readlines():
                    word = word.strip('\n')
                    computed_digest = hash.md5_crypt.encrypt(word, salt=salt)
                    crypt_word = computed_digest.split("$")[3]
                    if crypt_word == digest:
                        print("[+] Found Password: " + word)
                        return
        if alg == 'sha-512':
            salt = crypt_password.split("$")[2]
            digest = crypt_password.split("$")[3]
            dict_file = open('dictionary.txt', 'r')
            for word in dict_file.readlines():
                word = word.strip('\n')
                computed_digest = hash.sha512_crypt.encrypt(word, salt=salt, rounds=5000)
                crypt_word = computed_digest.split("$")[3]
                if crypt_word == digest:
                    print("[+] Found Password: " + word)
                    return

    print("[-] Password Not Found.")
    return


def main():
    pass_file = open('passwords.txt')
    for line in pass_file.readlines():
        if ":" in line:
            user = line.split(':')[0]
            crypt_pass = line.split(':')[1].strip(' ')
            print("[*] Cracking Password For: " + user)
            test_password(crypt_pass, False, 'crypt')

    pass_file.close()
    pass_file = open('passwords2.txt')
    for line in pass_file.readlines():
        if ":" in line:
            user = line.split(':')[0]
            crypt_pass = line.split(':')[1].strip(' ')
            print("[*] Cracking Password For: " + user)

            hash_type = crypt_pass.split("$")[1]
            if hash_type == '6':
                enc_alg = 'sha-512'
            elif hash_type == '5':
                enc_alg = 'md5'
            else:
                print("[*] Unknown Encryption Algorithm: " + str(hash_type))
                return
        else:
            print("[*] Error. No ':' delimiter found. Line: " + line)

        if len(crypt_pass) > 0 and len(enc_alg) > 0:
            test_password(crypt_pass, False, enc_alg)


if __name__ == "__main__":
    main()
