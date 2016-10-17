#server.py
import socket
import time

# create a socket object
serversocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# get local machine name
host = socket.gethostname()

port = 9999
clientList = []
#bind to the port
serversocket.bind((host, port))

#queue up to 5 requests
#serversocket.listen(5)

while True:
    # recv UDP data
    data, addr = serversocket.recvfrom(1024)
    # addr is the tuple we need
    print "data recived from "+ str(addr) + " ;data = " + data
    #clientList.append(addr)
    if data == "GREETINGS":
        print "new client trying to connect"
        if addr in clientList:
            print "same client trying to connect again!"
            data = "dont send this message again!"
            serversocket.sendto(data, addr)
        # adding clients to cliets list, which is basically portnumbers
        else:
            clientList.append(addr)
    else:
        # broadcast data to all clients here:
        print "sending data to all "
        for x in clientList:
            print "sending : "+ str(x)
            msg = "<from "+x[0]+":"+str(x[1])+">: "+data
            serversocket.sendto(msg, x)


    print clientList

    #print("Got a connection from %s" % str(addr))
    #currentTime = time.ctime(time.time()) + "\r\n"
    #serversocket.sendto((currentTime.encode('ascii')), addr)
    # not clising socket for now
    #clientsocket.close()
