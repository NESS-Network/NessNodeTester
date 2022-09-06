import json
import sys
import urllib.parse
from lib.NessAuth import NessAuth
from Crypto.Hash import MD5


class Auth:

    data_user = {}
    data_node = {}

    def __init__(self):
        return

    def loadUser(self, username: str):
        filename = username + ".key.json"
        f = open("out/keys/user/" + filename, "r")
        return json.loads(f.read())

    def loadNode(self, url: str):
        filename = urllib.parse.quote_plus(url) + ".key.json"
        f = open("out/keys/node/" + filename, "r")
        return json.loads(f.read())

    def run(self, username: str, node_url: str):
        ness_auth = NessAuth()
        user = self.loadUser(username)
        node = self.loadNode(node_url)
        url = node_url + "/node/test/auth"

        user_private_key = user['keys']["private"][user['keys']['current']]

        auth_id = ness_auth.auth_id(user_private_key, node_url, node["nonce"], username, user["nonce"])

        print('*** User Auth ID ***')
        print(auth_id)

        return True


if len(sys.argv) == 3:
    tester = Auth()
    tester.run(sys.argv[1], sys.argv[2])
elif len(sys.argv) == 4:
    tester = Auth()
    tester.run(sys.argv[1], sys.argv[2], sys.argv[3])
else:
    print('Show Userhash and AuthID')
    print('Usage: python auth-id.py <username> <node URL>')
