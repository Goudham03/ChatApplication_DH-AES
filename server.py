from os import name
import socket
import select

HEADER_LENGTH = 1024

IP = "192.168.1.2"
PORT = 12000


server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

server_socket.bind((IP, PORT))
server_socket.listen()

sockets_list = [server_socket]

print("whats is socketlist", sockets_list)

# List of connected clients - socket as a key, user header and name as data
clients = {}

given_username = ['goudham', 'arun', 'guru']
given_password = ['goudham123', 'arun123', 'guru123']
given_publickeys = {'goudham':None, 'arun':None, 'guru':None}

username_list = []
userport_list = []

print(f'Listening for connections on {IP}:{PORT}...')

def sendBRequest(clients, user, notified_socket, request_msg):
    print("Broadcast request from",senderName, " message is ", request_msg)
    temp_list = [senderName, request_msg, '$GIVEN_BMSG~']
    
    print("this is going to sent", temp_list)
    temp = str(temp_list)
    temp = temp.encode('utf-8')
    message_header = f"{len(temp):<{1024}}".encode('utf-8')

    for client_socket in clients:
        if client_socket != notified_socket:
            client_socket.send(message_header + temp)

    return True   

def sendRequest(clients, user, notified_socket, request_uname, given_publickeys, given_username, request_msg):
    print("message for ", request_uname, "frm ", senderName, " message is ", request_msg)

    temp_list = [senderName, request_uname, request_msg, '$GIVEN_MSG~']
    
    print("this is going to sent", temp_list)
    temp = str(temp_list)
    temp_length = str(len(temp))
    temp_header = temp_length
    for i in range(1024):
        if len(temp_header) < 1024:
            temp_header = temp_header + " "

    for client_socket in clients:
        cdd = clients[client_socket]
        if client_socket != notified_socket and cdd["data"].decode("utf-8") == request_uname:
            message_header = temp_header.encode('utf-8')
            temp = temp.encode('utf-8')
            client_socket.send(message_header + temp)
        
            return True

def listRequest(clients, user, notified_socket, given_publickeys):
    print("entered list funtion for", senderName)
    temp_username_list = username_list
    print("this pk at list section", given_publickeys)
    if '$GIVEN_LIST~' not in temp_username_list:
        temp_username_list.append("$GIVEN_LIST~")

    temp_pk = given_publickeys
    temp_username_list.append(temp_pk)
    temp = str(temp_username_list)
    temp = temp.encode('utf-8')
    message_header = f"{len(temp):<{1024}}".encode('utf-8')
    print("active list : ", temp)
    for client_socket in clients:
        cdd = clients[client_socket]
        if client_socket == notified_socket and cdd["data"].decode("utf-8") == user['data'].decode('utf-8'):
            client_socket.send(message_header + temp)
            print("list sent")
            trs = username_list.pop()
            print("this is popped", trs)

            if '$GIVEN_LIST~' in username_list:
                username_list.remove('$GIVEN_LIST~')
            return True

def listLRequest(clients, user, client_socket, given_publickeys):
    print("entered list funtion for fresher")
    temp_username_list = username_list
    print("this pk at list section", given_publickeys)
    if '$GIVEN_LIST~' not in temp_username_list:
        temp_username_list.append("$GIVEN_LIST~")

    temp_pk = given_publickeys
    temp_username_list.append(temp_pk)
    temp = str(temp_username_list)
    temp = temp.encode('utf-8')
    message_header = f"{len(temp):<{1024}}".encode('utf-8')
    print("active list : ", temp)
    for ele in clients:
        if ele != client_socket:
            ele.send(message_header + temp)
    print("list sent")
    trs = username_list.pop()
    print("this is popped", trs)
    if '$GIVEN_LIST~' in username_list:
        username_list.remove('$GIVEN_LIST~')

    return True


# Handles message receiving
def receive_message(client_socket):
    global username_list
    global userport_list
    try:

        # Receive our "header" containing message length, it's size is defined and constant
        message_header = client_socket.recv(HEADER_LENGTH)

        # If we received no data, client gracefully closed a connection, for example using socket.close() or socket.shutdown(socket.SHUT_RDWR)
        if not len(message_header):
            return False

        # Convert header to int value
        message_length = int(message_header.decode('utf-8').strip())
       
        # Return an object of message header and message data
        return {'header': message_header, 'data': client_socket.recv(message_length)}

    except:
        return False

while True:
    
    read_sockets, _, exception_sockets = select.select(sockets_list, [], sockets_list)

    print("ths is read socket ", read_sockets)

    # Iterate over notified sockets
    for notified_socket in read_sockets:
        # If notified socket is a server socket - new connection, accept it
        if notified_socket == server_socket:

            # Accept new connection
            # That gives us new socket - client socket, connected to this given client only, it's unique for that client
            # The other returned object is ip/port set
            client_socket, client_address = server_socket.accept()

            # Client should send his name right away, receive it
            user = receive_message(client_socket) 

            # If False - client disconnected before he sent his name
            if user is False:
                continue

            request_message = user["data"].decode('utf-8')
            if "$LOGIN_REQUEST~" in request_message:
                request_message = eval(request_message)
                reply_msg = ['$LOGIN_INFO~']

                u_name_request = request_message[0]
                u_pwd_request = request_message[1]
                u_public_request = request_message[2]

                if u_name_request in given_username:
                    u_index = given_username.index(u_name_request)
                    
                    if given_password[u_index] == u_pwd_request:

                        if u_name_request in username_list:
                            reply_msg.append("$ALREADY_EXIST~")
                            reply_msg = str(reply_msg)
                            reply_msg = reply_msg.encode('utf-8')
                            message_header = f"{len(reply_msg):<{HEADER_LENGTH}}".encode('utf-8')
                            client_socket.send(message_header + reply_msg)
                            continue

                        print("Verified user signing")
                        reply_msg.append("$TRUE_DATA~")
                        reply_msg = str(reply_msg)
                        
                        # Add accepted socket to select.select() list
                        sockets_list.append(client_socket)

                        theName = u_name_request
                        thePort = client_address
                        given_publickeys[theName] = u_public_request

                        print("public key of", theName, "is", given_publickeys[theName])

                        for u in sockets_list:
                            if theName not in username_list:
                                username_list.append(theName)
                                userport_list.append(thePort)

                        # Also save username and username header
                        temp_user = user
                        temp_user = temp_user["data"].decode('utf-8')
                        temp_user = eval(temp_user)

                        user["data"] = temp_user[0].encode('utf-8')
                        user["header"] = f"{len(theName):<{HEADER_LENGTH}}".encode('utf-8')
                        
                        print("user", user)
                        
                        clients[client_socket] = user

                        print("client sock",clients[client_socket])

                        reply_msg = reply_msg.encode('utf-8')
                        message_header = f"{len(reply_msg):<{1024}}".encode('utf-8')
                        client_socket.send(message_header + reply_msg)
                        print("reply message sent")  

                        if len(username_list) > 1:
                            listLRequest(clients, user, client_socket, given_publickeys)

                        print("username_list update at login", username_list)
                        print('Accepted new connection from {}:{}, username: {}'.format(*client_address, theName))
                    
                    else:
                        print("Incorrect username or password")
                        reply_msg.append("$FALSE_DATA~")
                        reply_msg = str(reply_msg)
                        reply_msg = reply_msg.encode('utf-8')
                        message_header = f"{len(reply_msg):<{1024}}".encode('utf-8')
                        client_socket.send(message_header + reply_msg)
                        continue
                
                else:
                    print("Incorrect username or password")
                    reply_msg.append("$FALSE_DATA~")
                    reply_msg = str(reply_msg)
                    reply_msg = reply_msg.encode('utf-8')
                    message_header = f"{len(reply_msg):<{1024}}".encode('utf-8')
                    client_socket.send(message_header + reply_msg)
                    continue

            else:
                print("Someone is trying to connect : message_info :>", request_message)
                continue
   
        # Else existing socket is sending a message
        else:
            
            # Receive message
            message = receive_message(notified_socket)

            # If False, client disconnected, cleanup
            if message is False:
                print('Closed connection from: {}'.format(clients[notified_socket]['data'].decode('utf-8')))

                user = clients[notified_socket]

                deluserName = str(user["data"].decode('utf-8'))

                temp_delname = deluserName
                # Remove from list for socket.socket()
                sockets_list.remove(notified_socket)
                delindex = username_list.index(deluserName)
                username_list.remove(deluserName)
                userport_list.pop(delindex)
              
                print("new user list ", username_list)
                # Remove from our list of users
                del clients[notified_socket]

                
                temp = [deluserName, '$DEL_RESPONSE~']
                temp = str(temp)
                temp = temp.encode('utf-8')
                message_header = f"{len(temp):<{1024}}".encode('utf-8')
                for client_socket in clients:
                    client_socket.send(message_header + temp)

                print("Notification about disconnected user sent")
                continue

            # Get user by notified socket, so we will know who sent the message
            msg = message["data"].decode("utf-8")
            
            
            print("this is msg", msg)
            user = clients[notified_socket]
            print("this is user",user["data"])
            senderName = user['data'].decode('utf-8')

            # print("userlist at sending gate", username_list)            
            if "$REQUEST_LIST~" in msg:
                msg = eval(msg)
                listRequest(clients, user, notified_socket, given_publickeys)
                if listRequest:
                    continue


            if "$REQUEST_SEND~" in msg:
                msg = eval(msg)
                request_uname = msg[1]
                request_msg = msg[2]
                sendRequest(clients, user, notified_socket, request_uname, given_publickeys, given_username, request_msg)
                if sendRequest:
                    continue

            if "$REQUEST_BSEND~":
                msg = eval(msg)
                request_msg = msg[1]
                sendBRequest(clients, user, notified_socket, request_msg)
                if sendBRequest:
                    continue

            

    # It's not really necessary to have this, but will handle some socket exceptions just in case
    for notified_socket in exception_sockets:

        # Remove from list for socket.socket()
        sockets_list.remove(notified_socket)

        # Remove from our list of users
        del clients[notified_socket]