import socket, array
u = socket.socket(socket.AF_UNIX)
u.connect("/tmp/axfd.sock")
msg, anc, *_ = u.recvmsg(1024, socket.CMSG_LEN(4))
fd = array.array("i", anc[0][2])[0]
s = socket.socket(fileno=fd)
try:
    s.connect(("127.0.0.1", 9))
    print("BYPASSED: connect succeeded")
except OSError as e:
    print("denied:", e)
