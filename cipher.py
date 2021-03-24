import hashlib as hl
from math import floor


class Cipher:
    def __init__(self, rkey: bytes):
        self.key = hl.sha256(rkey)
        self.key_bytes = self.key.digest()
        self.key_hex_str = self.key.hexdigest()
        rkey = None

    def encipher(self, o: bytes) -> bytes:
        o_arr = bytearray(o)
        new_o_arr = o_arr

        # If first byte of key and byte at index (first byte % 32) are of different parity, reverse the bytes of the input.
        cndtn = not self.key_bytes[0] % 2 == (self.key_bytes[self.key_bytes[0] % 32] % 2)
        if cndtn:
            temp_arr = new_o_arr
            new_o_arr = bytearray()
            for b in temp_arr:
                new_o_arr.insert(0, b)

        # If previous condition was satisfied, set i to 0, otherwise set i to 31 (last byte of key).
        # Generate a new set of bytes by performing a bitwise XOR on each byte of the key and the byte of the key at index i.
        # For each byte in the new set, perform a bitwise XOR between the byte and all bytes of the input.
        i = 0 if cndtn else 31
        temp_key_arr = bytearray(self.key_bytes)
        for b_i in range(len(temp_key_arr)):
            temp_key_arr[b_i] ^= self.key_bytes[i]
        for b in temp_key_arr:
            for b_i in range(len(new_o_arr)):
                new_o_arr[b_i] ^= b

        # Iterate through each byte in the input. For each byte, generate a new key based on the current byte's position,
        # the previous byte's value, and the cipher key.
        # Extract a byte from the result of repeated hashing of the current byte's position together with
        # the previous byte's value. Extract another byte from the result of repeated hashing of the cipher key.
        # Iterate through the generated key. If the current index is equal to the 32nd mod of either
        # of the 2 bytes extracted from repeated hashes, replace the value in the generated key with the same index in the
        # result of hashing the current generated key value n times, where n = the value of the extracted byte which the
        # current index is equal to the 32nd mod of. Perform a bitwise XOR on the current byte of the input and the current
        # byte of the generated key. After iteration fo the generated key is complete, add the new byte to the result.
        temp_arr = new_o_arr
        new_o_arr = bytearray()
        temp_arr.append(0x00)

        for b_i in range(len(temp_arr) - 1):
            pos_hash = hl.sha256(str(b_i).encode("utf-8")).digest()
            temp_key_arr = bytearray()
            for k_i in range(len(self.key_bytes)):
                temp_key_arr.append((self.key_bytes[k_i] * pos_hash[k_i]) % 256)
            temp_key_arr.append(temp_arr[b_i - 1])
            temp_key_bytes = hl.sha256(bytes(temp_key_arr)).digest()

            new_b = temp_arr[b_i]

            temp_v_list = [None] * 3
            temp_v_list[0] = hl.sha256(bytes([temp_arr[b_i - 1]]) + str(b_i).encode("utf-8")).digest()
            temp_v_list[1] = hl.sha256(self.key_bytes).digest()

            depth = floor(temp_arr[b_i - 1] / 32)
            for _ in range(depth):
                temp_v_list[0] = hl.sha256(temp_v_list[0]).digest()

                temp_v_list[1] = hl.sha256(temp_v_list[1]).digest()

            temp_v_list[0] = temp_v_list[0][temp_arr[b_i - 1] % 32]

            temp_v_list[1] = temp_v_list[1][temp_arr[b_i - 1] % 32]

            i_d = {a % 32: a for a in temp_v_list[0:2]}

            for k_i in range(len(temp_key_bytes)):
                if k_i in i_d:
                    temp_v_list[2] = hl.sha256(temp_key_bytes[k_i:k_i + 1]).digest()
                    for _ in range(i_d[k_i]):
                        temp_v_list[2] = hl.sha256(temp_v_list[2]).digest()
                    temp_key_arr = bytearray(temp_key_bytes)
                    temp_key_arr[k_i] = temp_v_list[2][k_i]
                    temp_key_bytes = bytes(temp_key_arr)

                new_b ^= temp_key_bytes[k_i]

            new_o_arr.append(new_b)

        return bytes(new_o_arr)

    def decipher(self, o: bytes) -> bytes:
        o_arr = bytearray(o)
        new_o_arr = o_arr

        #
        temp_arr = new_o_arr
        new_o_arr = bytearray()
        new_o_arr.append(0x00)

        for b_i in range(len(temp_arr)):
            pos_hash = hl.sha256(str(b_i).encode("utf-8")).digest()
            temp_key_arr = bytearray()
            for k_i in range(len(self.key_bytes)):
                temp_key_arr.append((self.key_bytes[k_i] * pos_hash[k_i]) % 256)
            temp_key_arr.append(new_o_arr[b_i - 1])
            temp_key_bytes = hl.sha256(bytes(temp_key_arr)).digest()

            new_b = temp_arr[b_i]

            temp_v_list = [None] * 3
            temp_v_list[2] = hl.sha256(bytes([new_o_arr[b_i - 1]]) + str(b_i).encode("utf-8")).digest()
            temp_v_list[0] = hl.sha256(bytes([new_o_arr[b_i - 1]]) + str(b_i).encode("utf-8")).digest()

            temp_v_list[1] = hl.sha256(self.key_bytes).digest()

            depth = floor(new_o_arr[b_i - 1] / 32)
            for _ in range(depth):
                temp_v_list[0] = hl.sha256(temp_v_list[0]).digest()

                temp_v_list[1] = hl.sha256(temp_v_list[1]).digest()

            temp_v_list[0] = temp_v_list[0][new_o_arr[b_i - 1] % 32]

            temp_v_list[1] = temp_v_list[1][new_o_arr[b_i - 1] % 32]

            i_d = {a % 32: a for a in temp_v_list[0:2]}

            for k_i in range(len(temp_key_bytes)):
                if k_i in i_d:
                    temp_v_list[2] = hl.sha256(temp_key_bytes[k_i:k_i + 1]).digest()
                    for _ in range(i_d[k_i]):
                        temp_v_list[2] = hl.sha256(temp_v_list[2]).digest()
                    temp_key_arr = bytearray(temp_key_bytes)
                    temp_key_arr[k_i] = temp_v_list[2][k_i]
                    temp_key_bytes = bytes(temp_key_arr)

                new_b ^= temp_key_bytes[k_i]

            if b_i == 0:
                del new_o_arr[0]
            new_o_arr.append(new_b)

        #
        cndtn = not self.key_bytes[0] % 2 == (self.key_bytes[self.key_bytes[0] % 32] % 2)

        i = 0 if cndtn else 31
        temp_key_arr = bytearray(self.key_bytes)
        for b_i in range(len(temp_key_arr)):
            temp_key_arr[b_i] ^= self.key_bytes[i]
        for b in temp_key_arr:
            for b_i in range(len(new_o_arr)):
                new_o_arr[b_i] ^= b

        #
        if cndtn:
            temp_arr = new_o_arr
            new_o_arr = bytearray()
            for b in temp_arr:
                new_o_arr.insert(0, b)

        return bytes(new_o_arr)
