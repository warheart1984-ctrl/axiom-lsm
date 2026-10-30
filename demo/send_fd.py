import socket, array, time
u = socket.socket(socket.AF_UNIX)
u.bind("/tmp/axfd.sock")
u.listen(1)
s = socket.socket()
c, _ = u.accept()
c.sendmsg([b"x"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [s.fileno()]))])
time.sleep(1)
