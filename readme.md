# NESS Node Tester - test suit for NESS nodes
### codegen.py

 Private and public code generation for user (client) and node

 Usage:
```
# Code generator for Ness nodes
### DESCRIPTION:
  Generates ciphers for NESS nodes and NESS node clients
  Works on ed25519 for keypairs and Blowfish or AES for symmetrical ciphers
### DIRECTORIES:
 'out/keys/node/*.key.json' - generated nodes
 'out/keys/user/*.key.json' - generated users
### USAGE:
#### Generate user
python codegen.py -ug username 10 "Main,blowfish,16;Second,aes,8" "Hello World,test"
python codegen.py --user-generate username 10 "Main,blowfish,16;Second,aes,8" "Hello World,test"
  Generates user with username 'username' with 10 keypairs
  Main,blowfish,16 - generate Blowfish cipher 16 bytes long with name 'First'
  Second,aes,8 - generate AES cipher 8 bytes long with name 'Second'
  "Hello World,test" - coma separated tags
#### Show generated user
python codegen.py -us username
python codegen.py --user-show username
#### Show <WORM> part of generated user
python codegen.py -usw username
python codegen.py --user-show-worm username
#### Generate node
python codegen.py -ng http://my-ness-node.net 1 master-user-name "Test,My test node,Hello world"
python codegen.py --node-generate http://my-ness-node.net 24 master-user-name "Test,My test node,Hello world"
  master-user-name - username of existing user, which will became owner of funds of this node
  24 - tariff, ammount of NCH payed to node (master-user address) every 24 hours 
  "Test,My test node,Hello world" - coma separated tags
#### Show generated node
python codegen.py -ns http://my-ness-node.net
python codegen.py --node-show http://my-ness-node.net
#### Show <WORM> part of generated node
python codegen.py -nsw http://my-ness-node.net
python codegen.py --node-show-worm http://my-ness-node.net
#### Show version
python codegen.py -v
python codegen.py --version
#### Show this manual
python codegen.py -h
python codegen.py --help
```
### configen.py
 Configuration generation for node

 Usage: `python configen.py <node URL>`

## Testing of the node
* All users must be generated and stored in emercoin blockchain

### test-auth.py
 Authentication testing
 Run after codegen.py

 Usage: `python test-auth.py <username> <node URL>`
###  test-user.py
Request information about existing user
 * Address (is no address exists than it will be created)
 * Current balance (Coins and Hours, fee)
 * Is user active (has enough balance to use node)

Usage: `python test-user.py <username> <node URL>`
### test-withdraw.py
Withdraw coins and hours from existing user to external address

Usage: `python test-withdraw.py <node URL> <username> <address> <coins> <hours>`
```
<node URL> - node URL
<username> - Your username
<address> - External address
<coins> - Ammount of coins to withdraw
<hours> - Ammount of hours to withdraw
```
###  test_prng.py
Test PRNG service

Usage: `python test-user.py <username> <node URL>`
```
<node URL> - node URL
<username> - Your username
```
###  test_files.py
Test Files service

Usage:
```
Test Files Service
python test-auth.py <username> <node URL> quota --- show users quota (free,used,total)
python test-auth.py <username> <node URL> list --- users files list
python test-auth.py <username> <node URL> upload <filename> --- upload filename to node (with resume)
python test-auth.py <username> <node URL> fileinfo <file_id> --- fileinfo on uploaded file (includes links for download (dl) and public link (pub))
python test-auth.py <username> <node URL> download <file_id> --- download uploaded file (with resume)
```
```
<node URL> - node URL
<username> - Your username
<file_id> - Hash of file name (returned by fileinfo or list commands)
```
## Instalation
`pip install requests pynacl pycryptodome validators lxml`

## Links
* [Ness node]( https://github.com/NESS-Network/NessNode)
* [Dev blog](  https://ness-main-dev.medium.com)