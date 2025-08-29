#!/usr/bin/python3

import sys
import os
import csv
import hashlib
import subprocess
import random

CHECKER_CONFIG='default.cfg'
CHECKER_TESTS='tests.csv'
CHECKER_COMMAND='./ursulachecktester'
CHECKER_RESULT='Result code:'
CHECKER_RESULT_CODE='Code string:'

CHECKER_SECRET_STRING='secret'
DELIMITER=':'

def run_checker(task, salt, graph):
    result = None
    code = None
    with subprocess.Popen([CHECKER_COMMAND, CHECKER_CONFIG, task, str(salt), graph],
                          stdout=subprocess.PIPE) as proc:
        for line in proc.stdout.readlines():
            line = str(line, 'utf-8').strip()
            if line.find(CHECKER_RESULT) == 0:
                result = int(line[len(CHECKER_RESULT):].strip())
            elif line.find(CHECKER_RESULT_CODE) == 0:
                code = line[len(CHECKER_RESULT_CODE):].strip()
    return (result, code)

def generate_sha256(secret, task, salt, result):
    h = hashlib.new('sha256')
    h.update('{}:{}:{}:{}'.format(secret, task, salt, result).encode('utf-8'))
    return h.hexdigest()

def test_graph(secret, task, result, graph):
    salt = random.randint(1, 100000)

    print('Runnig checker {} {} with salt {}...'.format(task, graph, salt), end='')
    res, code = run_checker(task, salt, graph)
    assert res == result, "Wrong result {} (expected {}) while testing graph {}".format(res, result, graph)
    sha = generate_sha256(secret, task, salt, result)
    assert code == sha, "Wrong result code '{}' (expected '{}') while testing graph {}".format(code, sha, graph)
    print(' OK')
    
if __name__ == '__main__':

    # tasks to test - (task_uuid, result, path)
    Tasks = []
    Secret = None
    
    print('Current dir:', os.getcwd())

    reader = csv.reader(open(CHECKER_CONFIG), delimiter=DELIMITER)
    for row in reader:
        if len(row) != 2: continue
        if row[0] == CHECKER_SECRET_STRING:
            Secret = row[1].strip()
        else:
            Tasks.append((row[0], 3, row[1].strip())) # add all correst scripts as valid tasks

    if Secret is None:
        print('Bad config, cannot find the secret string')
        sys.exit(1)

    reader = csv.reader(open(CHECKER_TESTS), delimiter=DELIMITER)
    for row in reader:
        if len(row) != 3: continue
        Tasks.append((row[0], int(row[1]), row[2].strip())) # add all correst scripts as valid tasks

    print('Testing (total {}):'.format(len(Tasks)))
    for t in Tasks:
        test_graph(Secret, t[0], t[1], t[2])
    print('Done!')

    sys.exit(0)
