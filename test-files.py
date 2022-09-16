import json
import sys
import os
import math
import urllib.parse
from lib.NessAuth import NessAuth
from Crypto.Hash import MD5


class FilesTester:

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

    def joined(self, username: str, node_url: str):
        ness_auth = NessAuth()
        user = self.loadUser(username)
        node = self.loadNode(node_url)
        url = node_url + "/node/joined"

        user_private_key = user['keys']["private"][user['keys']['current']]

        result = ness_auth.get_by_two_way_encryption(url, 'test', node['public'], user_private_key, username)

        if result['result'] == 'error':
            print(" ~~~ Registration check FAILED ~~~ ")
            print(result['error'])
        else:
            if ness_auth.verify_two_way_result(node['verify'], result):
                result = ness_auth.decrypt_two_way_result(result, user_private_key)
                return json.loads(result)
            else:
                print(" ~~~ Registration check FAILED ~~~ ")
                print(" Verifying signature failed ")

        return False

    def quota(self, username: str, node_url: str):
        ness_auth = NessAuth()
        user = self.loadUser(username)
        node = self.loadNode(node_url)
        url = node_url + "/files/quota"

        user_private_key = user['keys']["private"][user['keys']['current']]

        joined = self.joined(username, node_url)

        if joined == False:
            return False

        result = ness_auth.get_by_two_way_encryption(url, 'test', node['public'], user_private_key, joined['shadowname'])

        if result['result'] == 'error':
            print(" ~~~ quota command FAILED ~~~ ")
            print(result['error'])
        else:
            if ness_auth.verify_two_way_result(node['verify'], result):
                print(" *** quota *** ")
                print(ness_auth.decrypt_two_way_result(result, user_private_key))
            else:
                print(" ~~~ quota command FAILED ~~~ ")
                print(" Verifying signature failed ")

                return False

        return True

    def list(self, username: str, node_url: str):
        ness_auth = NessAuth()
        user = self.loadUser(username)
        node = self.loadNode(node_url)
        url = node_url + "/files/list"

        user_private_key = user['keys']["private"][user['keys']['current']]

        joined = self.joined(username, node_url)

        if joined == False:
            return False

        result = ness_auth.get_by_two_way_encryption(url, 'test', node['public'], user_private_key, joined['shadowname'])

        if result['result'] == 'error':
            print(" ~~~ list command FAILED ~~~ ")
            print(result['error'])
        else:
            if ness_auth.verify_two_way_result(node['verify'], result):
                print(" *** list *** ")
                files = json.loads(ness_auth.decrypt_two_way_result(result, user_private_key))['files']

                print(files)
            else:
                print(" ~~~ list command FAILED ~~~ ")
                print(" Verifying signature failed ")

                return False

        return True

    def fileinfo(self, username: str, node_url: str, file_id: str):
        ness_auth = NessAuth()
        user = self.loadUser(username)
        node = self.loadNode(node_url)
        url = node_url + "/files/fileinfo"

        user_private_key = user['keys']["private"][user['keys']['current']]

        joined = self.joined(username, node_url)

        if joined == False:
            return False

        result = ness_auth.get_by_two_way_encryption(url, 'test', node['public'], user_private_key, joined['shadowname'], 
            {'file_id': file_id})

        if result['result'] == 'error':
            print(" ~~~ fileinfo command FAILED ~~~ ")
            print(result['error'])
        else:
            if ness_auth.verify_two_way_result(node['verify'], result):
                print(" *** fileinfo *** ")
                fileinfo = json.loads(ness_auth.decrypt_two_way_result(result, user_private_key))

                fileinfo['dl'] = node_url + "/files/download/" + joined['shadowname'] + "/" + fileinfo['id'] + "/" + ness_auth.auth_id(user_private_key, node_url, node["nonce"], username, user["nonce"])
                fileinfo['pub'] = node_url + "/files/pub/" + fileinfo['id'] + "-" + joined['shadowname'] + "-" + ness_auth.alternative_id(user_private_key, node_url, node["nonce"], username, user["nonce"])

                print(fileinfo)
            else:
                print(" ~~~ list command FAILED ~~~ ")
                print(" Verifying signature failed ")

                return False

        return True

    def upload(self, username: str, node_url: str, filename: str, block_size = 1024**2):
        ness_auth = NessAuth()
        user = self.loadUser(username)
        node = self.loadNode(node_url)
        url = node_url + "/files/touch"

        user_private_key = user['keys']["private"][user['keys']['current']]

        joined = self.joined(username, node_url)

        if joined == False:
            return False

        result = ness_auth.get_by_two_way_encryption(url, 'test', node['public'], user_private_key, joined['shadowname'], 
            {'filename': ness_auth.encrypt(filename, node['public'])})
        
        if result['result'] == 'error':
            print(" ~~~ touch command FAILED ~~~ ")
            print(result['error'])
        else:
            if ness_auth.verify_two_way_result(node['verify'], result):
                print(" *** File touch *** ")
                fileinfo = json.loads(ness_auth.decrypt_two_way_result(result, user_private_key))
                uploaded = fileinfo['size']
                file_size = os.path.getsize(filename)

                if uploaded >= file_size:
                    print (" *** Olready uploaded *** ")
                    return True

                blocks = math.ceil((file_size - uploaded) / block_size)
                url = node_url + "/files/append/" + fileinfo['id']

                file = open(filename, "rb")
                
                print("Uploading file ...", flush=True)

                for i in range(blocks):
                    file.seek(uploaded + (block_size * i))
                    data = file.read(block_size)

                    result = ness_auth.post_data_by_auth_id(data, url, user_private_key, node_url, node['nonce'], username, joined['shadowname'], user["nonce"])
                    if result['result'] == 'error':
                        print("")
                        print(" ~~~ Upload failed ~~~ ")
                        print(result['error'])
                        return False
                    else:
                        print("+", end = " ", flush=True)

                file.close()

                print ()
                print (" *** UPLOADED *** ")
            else:
                print(" ~~~ list command FAILED ~~~ ")
                print(" Verifying signature failed ")

                return False

        return True

    def download(self, username: str, node_url: str, file_id: str, block_size = 1024**2):
        ness_auth = NessAuth()
        user = self.loadUser(username)
        node = self.loadNode(node_url)
        url = node_url + "/files/fileinfo"
        url_dl = node_url + "/files/download/" + file_id

        user_private_key = user['keys']["private"][user['keys']['current']]

        joined = self.joined(username, node_url)

        if joined == False:
            return False

        result = ness_auth.get_by_two_way_encryption(url, 'test', node['public'], user_private_key, joined['shadowname'], 
            {'file_id': file_id})

        if result['result'] == 'error':
            print(" ~~~ fileinfo command FAILED ~~~ ")
            print(result['error'])
        else:
            if ness_auth.verify_two_way_result(node['verify'], result):
                print(" *** fileinfo OK *** ")
                fileinfo = json.loads(ness_auth.decrypt_two_way_result(result, user_private_key))

                fileinfo['dl'] = node_url + "/files/download/" + joined['shadowname'] + "/" + fileinfo['id'] + "/" + ness_auth.auth_id(user_private_key, node_url, node["nonce"], username, user["nonce"])
                fileinfo['pub'] = node_url + "/files/pub/" + fileinfo['id'] + "-" + joined['shadowname'] + "-" + ness_auth.alternative_id(user_private_key, node_url, node["nonce"], username, user["nonce"])

                filename = fileinfo['filename']
                size = fileinfo['size']

                f = open(filename, 'ab')
                pos = f.tell()
                # print(pos)

                headers = {'Range': 'bytes=' + str(pos) + '-'}

                responce = ness_auth.get_responce_by_auth_id(url_dl, user_private_key, node_url, node['nonce'], 
                    username, joined['shadowname'], user['nonce'], headers)
                # print(responce.status_code)
                for block in responce.iter_content(chunk_size = block_size):
                    f.write(block)
                    print("+", end = " ", flush=True)

                f.close()

                print("")
                print(" *** DOWNLOAD OK *** ")

            else:
                print(" ~~~ list fileinfo FAILED ~~~ ")
                print(" Verifying signature failed ")

                return False

        return True

    def remove(self, username: str, node_url: str, file_id: str):
        ness_auth = NessAuth()
        user = self.loadUser(username)
        node = self.loadNode(node_url)
        url = node_url + "/files/remove"

        user_private_key = user['keys']["private"][user['keys']['current']]

        joined = self.joined(username, node_url)

        if joined == False:
            return False

        result = ness_auth.get_by_two_way_encryption(url, 'test', node['public'], user_private_key, joined['shadowname'], 
            {'file_id': file_id})
        
        if result['result'] == 'error':
            print(" ~~~ remove command FAILED ~~~ ")
            print(result['error'])
        else:
            if ness_auth.verify_two_way_result(node['verify'], result):
                print(" *** File removed *** ")
            else:
                print(" ~~~ list command FAILED ~~~ ")
                print(" Verifying signature failed ")

                return False

        return True


print('Test Files Service')

tester = FilesTester()

if len(sys.argv) == 4 and sys.argv[3] == 'quota':
    tester.quota(sys.argv[1], sys.argv[2])
elif len(sys.argv) == 4 and sys.argv[3] == 'list':
    tester.list(sys.argv[1], sys.argv[2])
elif len(sys.argv) == 5 and sys.argv[3] == 'upload':
    tester.upload(sys.argv[1], sys.argv[2], sys.argv[4])
elif len(sys.argv) == 5 and sys.argv[3] == 'fileinfo':
    tester.fileinfo(sys.argv[1], sys.argv[2], sys.argv[4])
elif len(sys.argv) == 5 and sys.argv[3] == 'download':
    tester.download(sys.argv[1], sys.argv[2], sys.argv[4])
elif len(sys.argv) == 5 and sys.argv[3] == 'remove':
    tester.remove(sys.argv[1], sys.argv[2], sys.argv[4])
else:
    print('Usage:')
    print('python test-files.py <username> <node URL> quota --- show users quota (free,used,total)')
    print('python test-files.py <username> <node URL> list --- users files list')
    print('python test-files.py <username> <node URL> upload <filename> --- upload filename to node')
    print('python test-files.py <username> <node URL> fileinfo <file_id> --- fileinfo on uploaded file')
    print('python test-files.py <username> <node URL> download <file_id> --- download uploaded file')
