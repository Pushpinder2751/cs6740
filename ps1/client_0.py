# client.py
import socket
import sys
import select

# create a socket object
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# get local machine name
host = socket.gethostname()

port = 9999
msg = "GREETINGS"
# connection to hostname on the port.
s.sendto(msg, (host, port))
print "Connedted to remote host, You can start sending messages now"
# Receive no more than 1024 bytes, UDP data

# this is important, otherwise code gets stuck
# this is part of select, this checks for inputs
# as the input comes in the inputready, we check for it
# and then we display the output accordingly
input = [s, sys.stdin]

while True:
    inputready, outputready, exceptready = select.select(input, [], [])

    for i in inputready:
        # message is displayed if client types
        if i == sys.stdin:
            msg = sys.stdin.readline()
            s.sendto(msg, (host, port))
        # message is displayed if server has some other message.
        elif i == s:
            data, addr = s.recvfrom(1024)
            print data

# for debugging
#print("The time got from the server is %s" % data.decode('ascii'))
