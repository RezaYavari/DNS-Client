# by a55236 | Ana Nunes (  16/02/2017 )
# update by Reza Yavari  (  01/12/2020 )
# written using only the default python libraries
# written in python 3 - can't guarantee backwards compatibility with python 2
# information to display and its formatting were chosen based on nslookup's interface

from socket import *
from secrets import *

# using UDP
clientSocket = socket(AF_INET, SOCK_DGRAM)

# localDNS = '192.168.1.254' # home
# localDNS = '193.136.224.100' # ualg
localDNS = '8.8.8.8'  # google
portnumber = 53

# setting up header
transaction_id = bytearray()
transaction_id.append(randbits(8))
transaction_id.append(randbits(8))
header = bytearray()
header.extend(transaction_id)
# Flags: 0000 0001 0000 0000 (recursion flag on)
header.append(0x01)
header.append(0x00)
# Question count: 1
header.append(0x00)
header.append(0x01)
# Answer count: 0
header.append(0x00)
header.append(0x00)
# Authority resource count: 0
header.append(0x00)
header.append(0x00)
# Additional Resource count: 0
header.append(0x00)
header.append(0x00)

# reading input (using simplified version of nslookup's formatting)
print("------------------------------------------------")
print("[hostname] (-type=[type])\nSupported types are A, AAAA, NS, CNAME, PTR, MX.")
print("------------------------------------------------")
print("www.uni-marburg.de -type=A")
print("www.uni-marburg.de -type=AAAA")
print("www.uni-marburg.de -type=NS")
print("www.uni-marburg.de -type=CNAME")
print("137.248.1.72 -type=PTR")
print("www.uni-marburg.de -type=MX")

input_str = input(
    '\nPlease Enter hostname and type :\n\n')


# parsing input
input_list = input_str.split()
try:
    labels = input_list[0].split('.')
except IndexError:
    print('Please insert a query.')
    clientSocket.close()
    quit(0)


def check_type_arg(index):
    try:
        type_str = input_list[index]
    except IndexError:
        return False
    return True


type = bytearray()

# due to the abundance of possible request types, only a few basic ones will be implemented
type_dict = {
    'A': '0x01', 'NS': '0x02',
    'CNAME': '0x05', 'PTR': '0x0C',
    'MX': '0x0F', 'SOA': '0x06',
    'AAAA': '0x1C'
    # , 'SRV': '0x21',
    # 'IXFR': '0xFB', 'AXFR': '0xFC'
}

if check_type_arg(1):
    if input_list[1].startswith("-type="):
        try:
            type_str = input_list[1][6:]
            type.append(0x00)
            type.append(int(type_dict[type_str], 16))
        except (IndexError, KeyError) as e:
            print('Invalid query.')
            clientSocket.close()
            quit(0)
    else:
        print('Invalid query.')
        clientSocket.close()
        quit(0)
else:
    type_str = 'A'
    type.append(0x00)
    type.append(0x01)

# setting up hostname
# special input parsing for PTR types
hostname = bytearray()
if type_str != 'PTR':
    for label in labels:
        hostname.append(len(label))
        hostname.extend(label.encode('utf-8'))
else:
    for label in reversed(labels):
        hostname.append(len(label))
        hostname.extend(label.encode('utf-8'))
    hostname.append(7)
    hostname.extend('in-addr'.encode('utf-8'))
    hostname.append(4)
    hostname.extend('arpa'.encode('utf-8'))
hostname.append(0x00)

# setting up query
query = bytearray()
query.extend(header)
query.extend(hostname)
query.extend(type)
query.append(0x00)
query.append(0x01)
query_len = len(query)

clientSocket.sendto(query, (localDNS, portnumber))

message, serverAddress = clientSocket.recvfrom(2048)
i = 1
# check if response
while (message[:2] != transaction_id):
    message, serverAddress = clientSocket.recvfrom(2048)
    i = i+1
    if i > 3:
        clientSocket.close()
        quit(0)

# check return code
check = message[3]
check = bin(check)[2:]
if (check[4:] == '0011') and (type_str != 'PTR'):
    print('Can\'t find ' + input_list[0] + ': The domain doesn\'t exist')
    clientSocket.close()
    quit(0)
elif check[4:] != '0000':
    print('Can\'t find ' + input_list[0])
    clientSocket.close()
    quit(0)

# check if authoritative
check = message[2]
check = bin(check)[2:]
print('')
if check[5] == '0':
    print('Non-authoritative answer:')
else:
    print('Authoritative answer:')

# check number of resources
# only parsing answers for the sake of simplicity
ans_cnt = int.from_bytes(message[6:8], byteorder='big')
auth_cnt = int.from_bytes(message[8:10], byteorder='big')
add_cnt = int.from_bytes(message[10:12], byteorder='big')

def_space = 10
start = query_len
total_len = 0

# reverse the type dictionary for hex strings lookup
reverse_type_dict = {i[1]: i[0] for i in type_dict.items()}

# parse ipv4 address


def parse_ip(r_len, first):
    res = ''
    for i in range(r_len):
        res += str(message[(first+i)])
        res += '.'
    return res[:-1]

# parse ipv6 address


def parse_ipv6(r_len, first):
    res = ''
    for i in range(0, r_len, 2):
        temp = format(message[(first+i)], '0x')
        temp += format(message[(first+i+1)], '02x')
        if all(v == '0' for v in temp):
            if not(res[-2:] == '::'):
                res += ':'
        else:
            res = res + temp + ':'
    return res[:-1]

# parse name


def parse_name(first):
    i = 0
    res = ''
    while(1):
        h_len = message[first+i]
        # check for byte that indicates the info is already present somewhere else in the message
        if h_len == 192:
            # grab that info and advance
            res += parse_name(message[first + i + 1])[0]
            res += '.'
            i = i+2
            break
        # check for byte that indicates the end of the name
        if h_len == 0:
            i += 1
            break
        # read current label and add '.'
        res += message[(first+i+1):(first+i+h_len + 1)].decode('utf-8')
        res += '.'
        i = i + h_len + 1
    return (res[:-1], i)

# parse each resource
# divided formatting by type, mostly self-explanatory
# formatting based on nslookup's


def parse_resource(start):
    name = parse_name(start)[0]
    n_len = parse_name(start)[1]
    try:
        for key, value in type_dict.items():
            if key == type_str:
                type = key
    except KeyError:
        type = '0'
    ans_len = int.from_bytes(
        message[(start+8+n_len):(start+10+n_len)], byteorder='big')

    if type == 'A':
        if (type_str == 'A'):
            print('Name: ' + name)
            print('Address: ' + parse_ip(ans_len, start+10+n_len))
        else:
            print(name + '  internet address = ' +
                  parse_ip(ans_len, start+10+n_len))

    if type == 'AAAA':
        if (type_str == 'AAAA'):
            print('Name: ' + name)
            print('Address: ' + parse_ipv6(ans_len, start+10+n_len))
        else:
            print(name + '  internet address = ' +
                  parse_ipv6(ans_len, start+10+n_len))
    if type == 'NS':
        print(name + '\t' + 'nameserver : ' + parse_name(start+10+n_len)[0])

    if type == 'SOA':
        print(name)
        newstart = start+10+n_len
        ntemp = parse_name(newstart)
        newstart += ntemp[1]
        print('\t' + 'primary name server = ' + ntemp[0])
        ntemp = parse_name(newstart)
        newstart += ntemp[1]
        print('\t' + 'responsible mail addr = ' + ntemp[0])
        print('\t' + 'serial = ' +
              str(int.from_bytes(message[(newstart):(newstart+4)], byteorder='big')))
        print('\t' + 'refresh = ' +
              str(int.from_bytes(message[(newstart+4):(newstart+8)], byteorder='big')))
        print('\t' + 'retry = ' +
              str(int.from_bytes(message[(newstart+8):(newstart+12)], byteorder='big')))
        print('\t' + 'expire = ' +
              str(int.from_bytes(message[(newstart+12):(newstart+16)], byteorder='big')))
        print('\t' + 'default TTL = ' +
              str(int.from_bytes(message[(newstart+16):(newstart+20)], byteorder='big')))

    if type == 'PTR':
        print(name + '\t' + 'name = ' + parse_name(start+10+n_len)[0])

    if type == 'MX':
        pref = str(int.from_bytes(
            message[(start+10+n_len):(start+12+n_len)], byteorder='big'))
        print(name + '\t' + 'MX preference = ' + pref +
              ', mails exchanger = ' + parse_name(start+12+n_len)[0])

    return ans_len+n_len


# parse answer records if they exist
for i in range(ans_cnt):
    ans_len = parse_resource(start)
    start = start+def_space+ans_len

# parse authoritative records if they exist
for i in range(auth_cnt):
    if(i == 0):
        print('')
    ans_len = parse_resource(start)
    start = start+def_space+ans_len

# parse additional records if they exist
for i in range(add_cnt):
    if(i == 0):
        print('')
    ans_len = parse_resource(start)
    start = start+def_space+ans_len


clientSocket.close()
