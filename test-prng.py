import json
import sys
import urllib.parse
from lib.NessAuth import NessAuth


class AuthTester:

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

    def test(self, username: str, node_url: str):
        ness_auth = NessAuth()
        user = self.loadUser(username)
        node = self.loadNode(node_url)

        user_private_key = user['keys']["private"][user['keys']['current']]

        result = ness_auth.get_by_auth_id(node_url + "/prng/seed", user_private_key, node_url, node["nonce"], username,
                                          user["nonce"])

        if result['result'] == 'error':
            print(" ~~~ FAILED ~~~ ")
            print(result['error'])
        else:
            print(" *** SEED OK !!! *** ")
            print(result['data']['seed'])


        return True


print('Test PRNG service')

if len(sys.argv) == 3:
    tester = AuthTester()
    tester.test(sys.argv[1], sys.argv[2])
else:
    print('Usage: python test-prng.py <username> <node URL>')
