#!/usr/bin/python

from Crypto.Cipher import AES
import scrypt
import hashlib
from pybitcointools import *
import binascii
import base58
from colored import fg, bg, attr



# BIP0038 proposal test cases for non-ec multiply mode verified
# Additional test cases verified with bitaddress.org

# TODO:
# verify encrypted privkey checksum before decrypting?





def bip38_decrypt(encrypted_privkey,passphrase):
    '''BIP0038 non-ec-multiply decryption. Returns WIF privkey.'''
    encrypt=(encrypted_privkey)
    d = base58.b58decode(encrypted_privkey)
    d = d[2:]
    flagbyte = d[0:1]
    d = d[1:]
    if flagbyte == '\xc0':
        compressed = False
    if flagbyte == '\xe0':
        compressed = True
    addresshash = d[0:4]
    d = d[4:-4]
    key = scrypt.hash(passphrase,addresshash, 16384, 8, 8)
    derivedhalf1 = key[0:32]
    derivedhalf2 = key[32:64]
    encryptedhalf1 = d[0:16]
    encryptedhalf2 = d[16:32]
    aes = AES.new(derivedhalf2, AES.MODE_ECB)
    decryptedhalf2 = aes.decrypt(encryptedhalf2)
    decryptedhalf1 = aes.decrypt(encryptedhalf1)
    priv = decryptedhalf1 + decryptedhalf2
    priv = binascii.unhexlify('%064x' % (long(binascii.hexlify(priv), 16) ^ long(binascii.hexlify(derivedhalf1), 16)))
    pub = privtopub(priv)
    if compressed:
        pub = encode_pubkey(pub,'hex_compressed')
        wif = encode_privkey(priv,'wif_compressed')
    else:
        wif = encode_privkey(priv,'wif')
    addr = pubtoaddr(pub)
    addresshass = hashlib.sha256(hashlib.sha256(addr).digest()).digest()[0:4]
    privkey = encode_privkey(wif,'hex')
    encryptedhalf3 = aes.encrypt(binascii.unhexlify('%0.32x' % (long(privkey[0:32], 16) ^ long(binascii.hexlify(derivedhalf1[0:16]), 16))))
    encryptedhalf4 = aes.encrypt(binascii.unhexlify('%0.32x' % (long(privkey[32:64], 16) ^ long(binascii.hexlify(derivedhalf1[16:32]), 16))))
    encrypted = ('\x01\x42' + flagbyte + addresshass + encryptedhalf3 + encryptedhalf4)
    encrypted += hashlib.sha256(hashlib.sha256(encrypted).digest()).digest()[:4]
    encrypted2 = base58.b58encode(encrypted)
    if hashlib.sha256(hashlib.sha256(addr).digest()).digest()[0:4] != addresshash:
    	print("%s PASSWORD INCORRECT%s" %(fg(1), attr(0)))
    	print(" ")
    	print(" address : "  "  " + addr)
    	print("  wif    :" "   " + wif)
    	print("_"*(65))
    if encrypted2 == encrypt:
    	print("%s PASSWORD FOUND UNLOCKED%s" %(fg(2), attr(0)))
    	print(" ")
    	print(" address : "  "  " + addr)
    	print("  wif    :" "   " + wif)
    	print("_"*(65))
    	s1 = str(wif)
    	s2 = addr
    	f=open(u"bip38_unlocked.txt","a")
    	f.write(s1)
    	f.write(s2)
    	f.close()
    	
    return wif