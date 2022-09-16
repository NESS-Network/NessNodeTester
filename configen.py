import json
import os
import sys
import urllib.parse
from Crypto.Random import get_random_bytes

print('Configen')
print('Generates node config from previously generated node by Codegen')


class Configen:

    def loadNode(node_url: str):
        filename = urllib.parse.quote_plus(node_url) + ".key.json"
        f = open("out/keys/node/" + filename, "r")
        return json.loads(f.read())

    def saveNode(node_url: str):
        node = Configen.loadNode(node_url)

        config_node = {
            "nonce": node["nonce"],
            "private": node["private"],
            "public": node["public"],
            "url": node["url"],
            "tariff": node["tariff"],
            "verify": node["verify"],
            "master-user": node["master-user"],
            "period" : "7200",
            "delta" : "1200",
            "slots" : "10",
        }

        filename = "out/config/node.json"
        f = open(filename, "w")
        f.write(json.dumps(config_node, indent=4, sort_keys=True))

        config_emer = {
            "host": "localhost",
            "port": 8332,
            "user": "user",
            "password": "password"
        }

        filename = "out/config/emer.json"
        f = open(filename, "w")
        f.write(json.dumps(config_emer, indent=4, sort_keys=True))

        config_ness = {
            "host": "localhost",
            "port": 6420,
            "wallet_id": "wallet.wlt",
            "password": "password"
        }

        filename = "out/config/ness.json"
        f = open(filename, "w")
        f.write(json.dumps(config_ness, indent=4, sort_keys=True))

        config_prng = {
            "seed": "/tmp/seed.txt",
            "seed-big": "/tmp/seed-big.txt",
            "numbers": "/tmp/numbers.json",
            "numbers-big": "/tmp/numbers-big.json",
            "numbers-i256": "/tmp/i256.json",
            "numbers-h256": "/tmp/h256.json"
        }

        filename = "out/config/prng.json"
        f = open(filename, "w")
        f.write(json.dumps(config_prng, indent=4, sort_keys=True))

        users_addresses = {}

        filename = "out/config/users_addr.json"
        f = open(filename, "w")
        f.write(json.dumps(users_addresses, indent=4, sort_keys=True))
        os.chmod(filename, 0o666)

        config_files = {
            "dir": "storage",
            "quota": "100MB",
            "salt": b64encode(get_random_bytes(16)).decode('utf-8'),
        }

        filename = "out/config/files.json"
        f = open(filename, "w")
        f.write(json.dumps(config_files, indent=4, sort_keys=True))


if len(sys.argv) == 2:
    node_url = sys.argv[1]
    Configen.saveNode(node_url)
    print('Config generated !')
    print('Move all generated *.json files from "out/config/*.json" to ~/.ness/*.json')
else:
    print('Usage: python configen.py <node URL>')