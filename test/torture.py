from socket import socket, getaddrinfo, IPPROTO_UDP
import argparse
from select import select
parser = argparse.ArgumentParser(description='Tests if the ts3init module, can withstand heavy loads.')
parser.add_argument('host', help='target host')
parser.add_argument('-p', dest='port', type=int, default=9987, help='target port')
parser.add_argument('-n', dest='number_of_packets', type=int, default=100000, help='number of packets to send')
args = parser.parse_args()

target = getaddrinfo(args.host, args.port, 0, 0, IPPROTO_UDP)[0]
print("-" * 40)
print("Test: ts3init_reset")
print("Target: %s:%i" % target[4])
print("-" * 40)
print("\n")

print("Sending %i packets..." % args.number_of_packets)

sock = socket(*target[0:3])

send = 0
sendErrors = 0
recieved = 0
invalid = 0
try:
    sock.connect(target[4])
    sock.setblocking(False)
    finished_writing = False
    while True:
        (canRead, canWrite, _) = select([sock.fileno()], [sock.fileno()] if send < args.number_of_packets else [] , [], 1)
        if canRead:
            data = sock.recv(128)
            if not data == b'TS3INIT1\x65\x00\x88\x05\x00':
                invalid += 1
            recieved += 1
        if canWrite:
            try:
                sock.send(str(send).encode())
                send += 1
            except:
                sendErrors += 1                
        if not canRead and not canWrite:
            break
finally:
    sock.close()
    print("send: %i(errors: %i); recieved: %i; invalid: %i" % (send, sendErrors, recieved, invalid))
