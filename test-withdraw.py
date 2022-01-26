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

    def test(self, node_url: str, username: str, address: str, coins: float, hours: int):
        ness_auth = NessAuth()
        user = self.loadUser(username)
        node = self.loadNode(node_url)

        user_private_key = user['keys']["private"][user['keys']['current']]

        wdata = json.dumps({'coins': coins, 'hours': hours, 'to_addr': address})
        url = node_url + "/node/withdraw"

        result = ness_auth.get_by_two_way_encryption(url, wdata, node['public'], user_private_key, username)

        if result['result'] == 'error':
            print(" ~~~ Withdraw failed ~~~ ")
            print(result['error'])
        else:
            if ness_auth.verify_two_way_result(node['verify'], result):
                print(" *** Withdraw OK *** ")
                print("Nodes answer: ")
                print(ness_auth.decrypt_two_way_result(result, user_private_key))
            else:
                print(" ~~~ Withdraw FAILED ~~~ ")
                print(" Verifying signature failed ")

        return True


print('Test withdraw')

if len(sys.argv) == 6:
    tester = AuthTester()
    tester.test(sys.argv[1], sys.argv[2], sys.argv[3], float(sys.argv[4]), int(sys.argv[5]))
else:
    print('Usage: python test-withdraw.py <node URL> <username> <address> <coins> <hours>')
    print('<node URL> - node URL')
    print('<username> - Your username')
    print('<address> - External address')
    print('<coins> - Ammount of coins to withdraw')
    print('<hours> - Ammount of hours to withdraw')
