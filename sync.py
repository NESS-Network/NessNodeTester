import json
import sys
import urllib.parse


class Sync:
    pass

print('Node Synchronizer')

if len(sys.argv) == 4:
    sync = Sync()
    sync.test(sys.argv[1], sys.argv[2])
else:
    print('Usage: python sync.py <hostname:port> <username> <password>')
    print('  <hostname:port> - Emercoin RPC host:port (localhost:8332)')
    print('  <username> - Emercoin RPC user')
    print('  <password> - Emercoin RPC password')
