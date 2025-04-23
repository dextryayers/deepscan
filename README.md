# deepscan
Penetration tools to find subdomains of a website quickly and simply, can also scan ports and provide information about subdomains.

## Tools Ethical Hacking

### main features
- deepscan subdomain
- scanning port
- provides information about the subdomain
- fast and simple

## Usage instructions:
```
Note Use Python 3.x

$ git clone https://github.com/dextryayers/deepscan
$ cd deepscan
$ pip3 install -r requirements.txt
$ python3 test.py -d tesla.com
```
## Usage options :

```
1. Basic scan (subdomains + HTTP status)
python3 test.py -d tesla.com

2. Deep scan with port scanning
python3 test.py -d tesla.com --scan-ports --deep-scan

3. With custom wordlist and output
python3 test.py -d tesla.com -w wordlist.txt -o results.json
```
