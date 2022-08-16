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

        result = ness_auth.get_by_auth_id(node_url + "/node/join", user_private_key, node_url, node["nonce"], username,
                                          user["nonce"])

        if result['result'] == 'error':
            print(" ~~~ TEST #1 join() FAILED ~~~ ")
            print(result['error'])
        else:
            print(" *** TEST #1 join() OK !!! *** ")
            print(result['data']['address'])

        result = ness_auth.get_by_auth_id(node_url + "/node/joined", user_private_key, node_url, node["nonce"], username,
                                          user["nonce"])

        if result['result'] == 'error':
            print(" ~~~ TEST #1 joined() FAILED ~~~ ")
            print(result['error'])
        else:
            print(" *** TEST #1 joined() OK !!! *** ")
            print(result['data']['joined'])

        result = ness_auth.get_by_auth_id(node_url + "/node/balance", user_private_key, node_url, node["nonce"], username,
                                          user["nonce"])

        if result['result'] == 'error':
            print(" ~~~ TEST #2 Balance() FAILED ~~~ ")
            print(result['error'])
        else:
            print(" *** TEST #2 Balance() OK !!! *** ")
            print(result['data']['balance'])

        result = ness_auth.get_by_auth_id(node_url + "/node/userinfo", user_private_key, node_url, node["nonce"], username,
                                          user["nonce"])

        if result['result'] == 'error':
            print(" ~~~ TEST #3 Userinfo() FAILED ~~~ ")
            print(result['error'])
        else:
            print(" *** TEST #3 Userinfo() OK !!! *** ")
            print(result['data']['userinfo'])

        return True


print('Test get user address and balance')

if len(sys.argv) == 3:
    tester = AuthTester()
    tester.test(sys.argv[1], sys.argv[2])
else:
    print('Usage: python test-user.py <username> <node URL>')
