import random


class PrivateKey(object):
    def __init__(self, p=None, g=None, x=None):
        self.p = p
        self.g = g
        self.x = x


class PublicKey(object):
    def __init__(self, p=None, g=None, h=None):
        self.p = p
        self.g = g
        self.h = h


def generate_keys(shared_p=6661, shared_g=666, assumed_private_key=66, bobs_public_key=2227):
    p = shared_p
    g = shared_g

    # if not declared. Use random values for public and private keys
    if assumed_private_key == -1 or bobs_public_key == -1:
        private_key = random.randint(1, (p - 1) // 2)
        public_key = pow(g, private_key, p)
    else:
        private_key = assumed_private_key
        public_key = bobs_public_key

    bob_public = PublicKey(p, g, public_key)
    bob_private = PrivateKey(p, g, private_key)

    return {'privateKey': bob_private, 'publicKey': bob_public}


def encrypt(key, msg):
    # pick random K
    k = random.randint(0, key.p)

    y1 = pow(key.g, k, key.p)
    y2 = (msg * pow(key.h, k, key.p)) % key.p

    cipher_pairs = [y1, y2]

    return cipher_pairs


def decrypt(key, cipher_array):
    y1 = cipher_array[0]
    y2 = cipher_array[1]

    normal_message = (int(y2) * (pow(int(y1), key.p - 1 - key.x, key.p))) % key.p

    return normal_message


# Since we know the answer, the base and power. We can try every available combination since we know that private key
# is a value =  2 <  private_key < p-2
# For K, we know that the value will always be < power.
def brute_force(base, power, answer):
    result = -1
    expect_public_key = answer
    for i in range(power):
        public_key = pow(base, i, power)
        if public_key == expect_public_key:
            result = i
            break

    return result


def change_msg_without_knowing_message(cipher_array, key, new_msg):
    # Get the first cypher key
    y1 = cipher_array[0]

    # Find out K used to generate y1
    k = brute_force(key.g, key.p, y1)

    # Encrypt a new message using the known public key and discovered k
    new_y2 = (new_msg * pow(key.h, k, key.p)) % key.p

    # Replace existing second part of the cipher
    cipher_array[1] = new_y2

    return cipher_array


def change_msg_knowing_message(cipher_array):
    # Get the second cypher key
    y2 = cipher_array[1]

    # Since we know that result of y2 = 2000. By multiplying with 3, we get 6000
    y2 = y2 * 3

    # Replace existing second part of the cipher
    cipher_array[1] = y2

    return cipher_array


if __name__ == '__main__':
    keys = generate_keys()  # Generates Public and private key

    priv = keys['privateKey']
    pub = keys['publicKey']

    message = 2000  # Alice wants to transfer 2000 dkk

    print("Alice's unencrypted message: " + str(message))

    cipher = encrypt(pub, message)  # Encrypt Alice's message

    print("Alice's encrypted message: ", cipher)
    plain = decrypt(priv, cipher)  # Decrypt Alice's message

    print("Bob decrypt the following message: " + str(plain))

    print("But Eve intercepted the message and brute forced bobs private key.")
    print("Bobs private key : " + str(brute_force(pub.g, pub.p, pub.h)))

    print("Also Mallory intercepted the message and changed the message.")
    # Change Alice's message if we dont know msg contents
    old_cipher = cipher.copy()
    newCyper = change_msg_without_knowing_message(old_cipher, pub, 6000)
    print("Mallory new cypher: ", newCyper)

    changed_plain = decrypt(priv, newCyper)

    print("Bob decrypt the following message: " + str(changed_plain))

    print("Alternatively if we know the content of the message. We can change the cipher as well.")
    # Change Alice's message if we know the content of the msg
    old_cipherr = cipher.copy()
    newCyperr = change_msg_knowing_message(old_cipherr)
    print("New cypher: ", newCyperr)

    changed_plains = decrypt(priv, newCyperr)

    print("Bob decrypt the following message: " + str(changed_plains))