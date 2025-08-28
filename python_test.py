#!/usr/bin/python3

import random
import hashlib
import string
from datetime import datetime
import subprocess

SHA256_COMMAND = './sha_test'

def __generate_str(n):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(n))
random.seed(datetime.now().timestamp())
                   
TEST_BLOCKS = ['',
               __generate_str(48),
               __generate_str(56),
               __generate_str(57),
               __generate_str(63),
               __generate_str(64),
               __generate_str(65),
               __generate_str(120),
               __generate_str(128),
               __generate_str(2000)]


                   
for block in TEST_BLOCKS:
    h = hashlib.new('sha256')
    byte_block = block.encode('utf-8')
    h.update(byte_block)
    digest1 = h.hexdigest()

    with subprocess.Popen([SHA256_COMMAND], stdin=subprocess.PIPE , stdout=subprocess.PIPE) as proc:
        proc.stdin.write(byte_block)
        proc.stdin.close()
        digest2 = str(proc.stdout.read(), 'utf-8').strip()

    if digest1 == digest2:
        print(len(byte_block), 'OK')
    else:
        print(len(byte_block), 'ERROR:', block, digest1, digest2)
        break
