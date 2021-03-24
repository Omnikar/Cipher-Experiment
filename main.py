from cipher import Cipher


# en1 = Cipher(b"bar")
# print("Key: " + en1.key_hex_str)
# enciphered = en1.encipher(u"foo".encode("utf-8"))
# print("Enciphered:", enciphered)
# print("Deciphered:", en1.decipher(enciphered))


rkey = input("Key: ")
en = Cipher(rkey.encode("utf-8"))

inp = input(": ").lower()

if inp == "encipher":

    path_source = input("File to encipher: ")
    path_dest = input("File to write to: ")

    file_source = open(path_source, "rb")
    file_dest = open(path_dest, "wb")

    file_dest.write(en.encipher(file_source.read()))

    file_source.close()
    file_dest.close()

elif inp == "decipher":

    path_source = input("File to decipher: ")
    path_dest = input("File to write to: ")

    file_source = open(path_source, "rb")
    file_dest = open(path_dest, "wb")

    file_dest.write(en.decipher(file_source.read()))

    file_source.close()
    file_dest.close()
