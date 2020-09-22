# -*- coding: utf-8 -*-
import base64
import hashlib

from Crypto import Random
from Crypto.Cipher import AES
from urllib import parse

AES_SECRET_KEY = 'e45e329feb5d925b'  # 此处16|24|32个字符 rebeyond md5加密后前16位
# padding算法
BS = len(AES_SECRET_KEY)
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s: s[0:-ord(s[-1:])]

class AES_ENCRYPT(object):
    def __init__(self):
        self.key = AES_SECRET_KEY
        self.mode = AES.MODE_CBC
        self.key_dict = {}

    def encryption(self, domain):
        b = hashlib.md5()
        b.update(domain.encode(encoding='utf-8'))
        return b.hexdigest()[0:16]

    def key_generate(self):
        with open('./resource/dictory/top500.txt', 'r') as f:
            for line in f:
                line = line.strip()
                self.key_dict[line] = self.encryption(line)

    # 冰蝎 php 解密
    def behinder_php_decrypt(self, text):
        bs = AES.block_size
        iv = bytes((0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        decode = base64.b64decode(text)
        for key, value in self.key_dict.items():
            cryptor = AES.new(value.encode("utf-8"), self.mode, iv)
            plain_text = None
            try:
                plain_text = cryptor.decrypt(decode).lower()
            except Exception as e:
                pass
            if plain_text:
                if b'eval' in plain_text or b'base64' in plain_text or b'"status"' in plain_text or b'"basicinfo"' in plain_text:
                    print('PHP decode success: The key is %s and The payload is %s ' % (key, str(plain_text)))
                    return plain_text
            else:
                plain_text = self.behinder_asp_decrypt(text)
                return plain_text

    # 冰蝎 asp 解密
    def behinder_asp_decrypt(self, text):
        bs = base64.b64decode(text)
        for key, value in self.key_dict.items():
            plain_text = ''
            i = 0
            while i < len(bs):
                tmp = bs[i] ^ bytes(value, encoding='utf-8')[i + 1 & 15]
                plain_text += chr(tmp)
                i += 1
            plain_text = bytes(plain_text, encoding='utf-8')
            if b'eval' in plain_text or b'base64' in plain_text or b'"status"' in plain_text or b'"basicinfo"' in plain_text:
                print('ASP decode success: The key is %s and The payload is %s ' % (key, str(plain_text)))
                return plain_text


    # 冰蝎 jsp 解密
    def behinder_jsp_decrypt(self, text):
        bs = AES.block_size
        mode = AES.MODE_ECB
        decode = base64.b64decode(text)
        for key, value in self.key_dict.items():
            cryptor = AES.new(value.encode("utf-8"), mode)
            plain_text = cryptor.decrypt(decode)
            if b'java' in plain_text:
                print('JSP decode success: The key is %s and The payload is %s ' %(key, str(plain_text)))
                return plain_text

    # 冰蝎 csharp 解密
    def behinder_csharp_decrypt(self, text):
        bs = AES.block_size
        mode = AES.MODE_CBC
        decode = base64.b64decode(text)
        for key, value in self.key_dict.items():
            iv = value.encode("utf-8")
            cryptor = AES.new(value.encode("utf-8"), mode, iv)
            plain_text = cryptor.decrypt(decode)
            if b'java' in plain_text:
                print('success: The key is %s and The payload is %s ' %(key, str(plain_text)))
                return plain_text


if __name__ == '__main__':
    aes_encrypt = AES_ENCRYPT()
    test_a = "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"
    aes_encrypt.key_generate()
    aes_encrypt.behinder_php_decrypt(test_a)
