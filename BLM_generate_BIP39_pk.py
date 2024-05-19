from bip32utils import BIP32Key
from bip32utils import BIP32_HARDEN
from bip32utils import Base58
import os, bip39

import codecs
import hashlib
import ecdsa
import base58

def pk_to_hash_unc_p2pkh(priv_key):
    private_key_bytes = codecs.decode(priv_key, 'hex')
    key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1).verifying_key
    key_bytes = key.to_string()
    key_hex = codecs.encode(key_bytes, 'hex')
    bitcoin_byte = b'04'
    public_key = bitcoin_byte + key_hex
    public_key_bytes = codecs.decode(public_key, 'hex')
    sha256_bpk = hashlib.sha256(public_key_bytes)
    sha256_bpk_digest = sha256_bpk.digest()
    ripemd160_bpk = hashlib.new('ripemd160')
    ripemd160_bpk.update(sha256_bpk_digest)
    ripemd160_bpk_digest = ripemd160_bpk.digest()
    ripemd160_bpk_hex = codecs.encode(ripemd160_bpk_digest, 'hex')
    return ripemd160_bpk_hex

def pk_to_hash_c_p2pkh(priv_key):
    private_key_bytes = codecs.decode(priv_key, 'hex')
    key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1).verifying_key
    key_bytes = key.to_string()

    if key_bytes[-1] & 1:
        bitcoin_byte = b'03'
    else:
        bitcoin_byte = b'02'

    key_bytes =  key_bytes[0:32]
    key_hex = codecs.encode(key_bytes, 'hex')
    public_key = bitcoin_byte + key_hex
    public_key_bytes = codecs.decode(public_key, 'hex')
    sha256_bpk = hashlib.sha256(public_key_bytes)
    sha256_bpk_digest = sha256_bpk.digest()
    ripemd160_bpk = hashlib.new('ripemd160')
    ripemd160_bpk.update(sha256_bpk_digest)
    ripemd160_bpk_digest = ripemd160_bpk.digest()
    ripemd160_bpk_hex = codecs.encode(ripemd160_bpk_digest, 'hex')
    return ripemd160_bpk_hex

def rp160hash_to_p2pkhAddress(ripemd160_pk_hex):
    network_bitcoin_public_key = b'00' + ripemd160_pk_hex
    network_bitcoin_public_key_bytes = codecs.decode(network_bitcoin_public_key, 'hex')
    sha256_nbpk = hashlib.sha256(network_bitcoin_public_key_bytes)
    sha256_nbpk_digest = sha256_nbpk.digest()
    sha256_2_nbpk = hashlib.sha256(sha256_nbpk_digest)
    sha256_2_nbpk_digest = sha256_2_nbpk.digest()
    sha256_2_hex = codecs.encode(sha256_2_nbpk_digest, 'hex')
    checksum = sha256_2_hex[:8]
    address_hex = (network_bitcoin_public_key + checksum).decode('utf-8')
    address = base58.b58encode(bytes(bytearray.fromhex(address_hex))).decode('utf-8')
    return address

with open('english.txt') as f:
    bip39_list = f.readlines()
bip39_list = [w.strip('\n') for w in bip39_list]

passphrase = ''
account_number = 0
mnemonic = 'moon tower food this real subject address total ten black'

flag = False
print("Starting search...")
for j in range(0, len(bip39_list)):
    for k in range(0, len(bip39_list)):
        try:
            seed = bip39.phrase_to_seed(mnemonic+' '+bip39_list[j]+' '+bip39_list[k], passphrase=passphrase)
            key = BIP32Key.fromEntropy(seed)
            for account_number in range(0,2):
                for i in range(0, 10):
                    pk = key.ChildKey(44 + BIP32_HARDEN).ChildKey(0 + BIP32_HARDEN).ChildKey(account_number + BIP32_HARDEN).ChildKey(0).ChildKey(i).PrivateKey().hex()
                    address_c = rp160hash_to_p2pkhAddress(pk_to_hash_c_p2pkh(pk))
                    address_unc = rp160hash_to_p2pkhAddress(pk_to_hash_unc_p2pkh(pk))
                    print(f"Checking mnemonic: {mnemonic} {bip39_list[j]} {bip39_list[k]}, Address C: {address_c}, Address UNC: {address_unc}")
                    if address_c == '1KfZGvwZxsvSmemoCmEV75uqcNzYBHjkHZ' or address_unc == '1KfZGvwZxsvSmemoCmEV75uqcNzYBHjkHZ':
                        found_mnemonic = f'{mnemonic} {bip39_list[j]} {bip39_list[k]}'
                        print(f'FOUND, mnemonic: {found_mnemonic}')
                        flag = True
                        with open('fundMnem.txt', 'a') as result_file:
                            result_file.write(found_mnemonic + '\n')
                        break
        except Exception as ex:
            print(f"Error: {ex}")
        if flag:
            break
    if flag:
        break

    if (j % 10 == 0) and (j != 0):
        print(f'{round(100*(j+1) / len(bip39_list),2)} %')

print("Search complete.")
