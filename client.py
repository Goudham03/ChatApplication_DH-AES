
from os import remove, set_inheritable, startfile

from tkinter import *
from tkinter import font
from tkinter import filedialog as fi

from PIL import Image
from PIL import ImageTk
from PIL import ImageOps

import socket
import select
import errno

from sympy import *

import math
from decimal import *

from threading import Thread

import ast
import time

from Crypto import *
from Crypto.Util.Padding import pad,unpad
import math
from decimal import *
import sys
import hashlib
import binascii,os
import base64
from Crypto.Cipher import AES
from Crypto import Random

from decimal import Decimal



#############   Tkinter Structure   ###############
#aspect ratio 16:9
H = int(576)
W = int(1024)

root_bg = '#121212'
panel_bg = '#1e1e1e'
incorrect_fg = '#fa4659'
correct_fg = '#3bd16f'

list_flag = 0
activeUsers = []
username_list = []
previous_list = []

#############    Main Panel is declared as root    ####################
# 1.login page
# 2.chat page

root = Tk()
root_icon = PhotoImage(file = "logo.png")
root.iconphoto(False, root_icon)
root.geometry('1024x576')
root.minsize(W, H)
root.maxsize(W, H)
root.title("DH secret chat application")
root.configure(background = root_bg)



BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

global start
global end

def encryptText(raw, password):
    start = Decimal(time.perf_counter())
    raw = str(raw)
    private_key = hashlib.sha256(password.encode("utf-8")).digest()
    print(len(private_key))
    raw = pad(raw)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    end = Decimal(time.perf_counter())
    print("Time to encrypt ", str(Decimal(end-start)))
    return base64.b64encode(iv + cipher.encrypt(raw.encode('utf-8')))
 
 
def decryptText(enc, password):
    start = Decimal(time.perf_counter())
    private_key = hashlib.sha256(password.encode("utf-8")).digest()
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    end = Decimal(time.perf_counter())
    print("Time to decrypt ", str(Decimal(end-start)))
    return unpad(cipher.decrypt(enc[16:]))


class User:

    def __init__(self, root, userlist_frame, username, public_key, available_user_frame):

        self.username = username
        self.userlist_frame = userlist_frame
        self.root = root
        self.flag = 0
        self.secretkey = 0
        self.available_user_frame = available_user_frame
        self.publickey = public_key
        self.count_msg = 0

        self.available_user_button = Button(self.available_user_frame, borderwidth=0, activebackground='#2e2e2e', activeforeground="#cccccc", text = self.username, relief = GROOVE, padx = 10, pady=5, font = ("Segoe UI semibold",12), bg = "#1e1e1e", fg = "#cccccc", command=lambda:self.chatRaiser())

        self.available_user_button.pack(fill=X, side=TOP, pady=1)
        self.available_user_button.tkraise()

        
        ##########  Actual chat frames  ############
        
        self.chataction_frame = Frame(self.root, bg='#121212')
        
        # live panel
        self.chatpanel_frame = Frame(self.chataction_frame, bg='#121212')
        
        # message
        self.message_list = Listbox(self.chatpanel_frame, relief = FLAT, bg = "#121212", highlightthickness=0, fg='#cccccc', activestyle = 'none', selectbackground = '#DBDADA', selectforeground = '#121212', font = ("Segoe UI",14))
         
        #   messenger
        self.message_entry = Entry(self.chataction_frame, state = NORMAL, borderwidth=5, selectbackground = "#1e1e1e", font = ("Segoe UI",14), relief = FLAT, fg = "#121212", bg = "#cccccc")
        self.send_button = Button(self.chataction_frame, height=1, text = "Send", relief = GROOVE, padx = 10, font = ("Segoe UI semibold",14), bg = "#1e1e1e", fg = "#cccccc", command=lambda:self.sentMessage())
        # user title
        self.client_frame = Frame(self.chataction_frame, bg='#2f2f2f') 
       

        self.client_title = Label(self.client_frame, text = self.username, pady = 10, fg = '#cccccc', bg = '#2f2f2f', font = ("Segoe UI semibold",14))
     
        self.requestSkey()
        

    
    def requestSkey(self): 
        self.secretkey = self.publickey**my_privatekey % primeNumber
        print("this my secret key", self.secretkey, " for ", self.username)
        print("this the requested pk", self.publickey)


    def disableButton(self):
        self.send_button["state"] = "disabled"
        self.client_title["fg"] = incorrect_fg

    def activeButton(self):
        self.send_button["state"] = "normal"
        self.client_title["fg"] = "#cccccc"



    def chatRaiser(self):

        if self.flag == 0:
            print("tht worked", self.username)
            self.available_user_button["borderwidth"] = 0
            self.chataction_frame.place(relheight=1, relwidth=0.7, relx=1, rely=1, anchor='se')
            self.chatpanel_frame.place(relheight=0.82, relwidth=1, relx=0,rely=0.51,anchor='w')
            self.message_list.pack(side = LEFT, expand = 1, fill = BOTH, padx = 5, pady = 5)
            self.message_entry.place(relheight=0.08, relwidth=0.8, relx=0, rely=1, anchor='sw')
            self.send_button.place(relheight=0.08, relwidth=0.2, relx=1, rely=1, anchor='se')
            self.client_frame.place(relheight=0.1, relwidth=1, relx=0, rely=0, anchor='nw')
            self.client_title.place(relheight=0.5, relwidth=0.5, rely=0.5, relx=0.5, anchor=CENTER)
            self.chataction_frame.tkraise()
            self.flag = 1
            
            
        else:
            self.available_user_button["borderwidth"] = 0
            self.chataction_frame.tkraise()
        

    

    def sentMessage(self):
        print("message called by"+ self.username)
        send_msg = []
        check_msg = str(self.message_entry.get())
        show_msg = check_msg
        
        if not check_msg:
            print("enter something")
        else:
            # sent message
            print("working")
            check_msg = encryptText(check_msg, str(self.secretkey))
            send_msg.append("$REQUEST_SEND~")
            send_msg.append(self.username)
            send_msg.append(check_msg)
            
            # message format ['REQUEST_SEND', 'receiver name', 'message']
            print("expected format",send_msg)
            send_msg = str(send_msg)
            send_msg = send_msg.encode('utf-8')
            message_header = f"{len(send_msg):<{HEADER_LENGTH}}".encode('utf-8')
            client_socket.send(message_header + send_msg)
            self.message_list.insert(self.count_msg, " [You] : "+show_msg)
            self.message_list.itemconfig(self.count_msg, bg='#1e1e1e')
            self.count_msg += 1
            self.message_entry.delete(0, END)

 

    def receivedMessage(self, msg):
        #   receive message
        msg = decryptText(msg, str(self.secretkey))
        msg = msg.decode('utf-8')
        self.available_user_button["borderwidth"] = 2
        self.message_list.insert(self.count_msg, " ["+self.username+"] : "+str(msg))
        self.message_list.itemconfig(self.count_msg, bg='#2f2f2f')
        self.count_msg += 1
        


    def raiser(self):
        self.chataction_frame.tkraise()




def broadcastRaiser(chataction_frame):
    BC_button["borderwidth"] = 0
    chataction_frame.tkraise()

   
def broadcastSend(message_entry, message_list, cnt):
    global count_msg
    count_msg = cnt
    print(" messagecount", count_msg)
    send_msg = []
    check_msg = str(message_entry.get())
    
    if not check_msg:
        print("enter something")
    elif ('$LOGIN_INFO~' not in check_msg) and ("$GIVEN_LIST~" not in check_msg) and ("$GIVEN_MSG~" not in check_msg) and ("$GIVEN_BMSG~" not in check_msg) and ("$DEL_RESPONSE~" not in check_msg) and ('$LOGIN_REQUEST~' not in check_msg):
        # sent message
        print("working")
        send_msg.append("$REQUEST_BSEND~")
        send_msg.append(str(message_entry.get()))
        
        # message format ['REQUEST_SEND', 'message']
        print("expected format",send_msg)
        send_msg = str(send_msg)
        send_msg = send_msg.encode('utf-8')
        message_header = f"{len(send_msg):<{HEADER_LENGTH}}".encode('utf-8')
        client_socket.send(message_header + send_msg)
        message_list.insert(count_msg, " [You] : "+check_msg)
        message_list.itemconfig(count_msg, bg='#1e1e1e')
        count_msg += 1
        message_entry.delete(0, END)
    else:
        print("You are not allowed to send this message")

def loginGate(message):
    global my_username
    if message[1] == "$TRUE_DATA~":
        print("login details verified")
        my_username = entered_uname
        login_status_frame["fg"] = correct_fg
        login_status_frame["text"] = "Verifying credentials"
        chatpage_raiser()
        return 1

    elif message[1] == "$FALSE_DATA~":
        login_status_frame["fg"] = incorrect_fg
        login_status_frame["text"] = "Incorrect username or password"
        about_frame.place(relheight=0.65, relwidth=0.575, relx=0.325, rely=0.5, anchor=CENTER)
        print("Incorrect Username or Password")
        return 0 

    elif message[1] == "$ALREADY_EXIST~":
        login_status_frame["fg"] = incorrect_fg
        login_status_frame["text"] = "You are already logged in."
        about_frame.place(relheight=0.65, relwidth=0.575, relx=0.325, rely=0.5, anchor=CENTER)
        print("User is already active")
        return 0

def refreshList(my_username):

    global given_publickeys

    given_publickeys = {'goudham': None, 'arun' : None, 'guru': None}

    send_msg = [my_username, '$REQUEST_LIST~']
    send_msg = str(send_msg)
    send_msg = send_msg.encode('utf-8')
    message_header = f"{len(send_msg):<{HEADER_LENGTH}}".encode('utf-8')
    client_socket.send(message_header + send_msg)
    print("looking for the list") 

def disconnectNotification(del_name, activeUsers):
    print(del_name, "disconnected")
    for obj in activeUsers:
        if obj.username == del_name:
            obj.disableButton()



def listRequest(rec_msg, my_username, flag, previous_list, activeUsers):
    print("my_username", my_username)
    global username_list
    
    list_flag = flag

    username_list = rec_msg
    temp_pk = username_list.pop()
    given_publickeys = temp_pk
    username_list.remove('$GIVEN_LIST~')

    print("active users in the func", activeUsers, list_flag)

    # remove my_username from the list
    username_list.remove(my_username)

    print("usename list deleting my name", username_list)


    previous_list = []
    for i in range(0,len(activeUsers)):
        previous_list.append(activeUsers[i].username)

    print("Previous list ", previous_list)


    if list_flag == 0:
        previous_list = username_list
        for u in username_list:
            temp_pk = given_publickeys[u]
            activeUsers.append(User(root, userlist_frame, u, temp_pk, available_user_frame))
        
        return 1

    else:
        if len(activeUsers) == 0:
            if len(username_list) > 0:
                for u in username_list:
                    temp_pk = given_publickeys[u]
                    activeUsers.append(User(root, userlist_frame, u, temp_pk, available_user_frame))

        else:
            for u in username_list:
                if u not in previous_list:
                    temp_pk = given_publickeys[u]
                    activeUsers.append(User(root, userlist_frame, u, temp_pk, available_user_frame))

                else:
                    for obj in activeUsers:
                        if obj.username == u:
                            temp_pk = given_publickeys[u]
                            obj.publickey = temp_pk
                            obj.requestSkey()
                            obj.activeButton()


    return 1
        




def directMessage(rec_msg, activeUsers):
    show_user = rec_msg[0]
    received_msg = rec_msg[2]

    for u in range(0,len(activeUsers)):
        if activeUsers[u].username == show_user:
            print("here", activeUsers[u].username)
            activeUsers[u].receivedMessage(received_msg)



def chatpage_raiser():
    
    global count_msg
    count_msg = 0

    login_frame.place_forget()
    about_frame.place_forget()

    userlist_frame.place(relheight=1, relwidth=0.3, relx=0, rely=1, anchor='sw')
    userlist_title.place(relheight=0.1, relwidth=1, relx=0, rely=0, anchor='nw')

    available_user_frame.place(relheight=0.82, relwidth=1, relx=0, rely=0.51, anchor='w')

    hint_root_frame.place(relheight=1, relwidth=0.7, relx=1, rely=1, anchor='se')
    hint_root_label.place(relheight=0.5, relwidth=0.5, relx=0.5, rely=0.5, anchor=CENTER)
    
    chataction_frame = Frame(root, bg='#121212')    
    chatpanel_frame = Frame(chataction_frame, bg='#121212')

    global message_list
    message_list = Listbox(chatpanel_frame, relief = FLAT, bg = "#121212", highlightthickness=0, fg='#cccccc', activestyle = 'none', selectbackground = '#DBDADA',
    selectforeground = '#121212', font = ("Segoe UI",14))
    message_list.pack(side = LEFT, expand = 1, fill = BOTH, padx = 5, pady = 5)

    message_entry = Entry(chataction_frame, state = NORMAL, borderwidth=5, selectbackground = "#1e1e1e", font = ("Segoe UI",14), relief = FLAT, fg = "#121212", bg = "#cccccc")
    send_button = Button(chataction_frame, height=1, text = "Send", relief = GROOVE, padx = 10, font = ("Segoe UI semibold",14), bg = "#1e1e1e", fg = "#cccccc", command=lambda:broadcastSend(message_entry, message_list, count_msg))

    client_frame = Frame(chataction_frame, bg='#2f2f2f') 
    client_title = Label(client_frame, text = "Broadcast Channel", pady = 10, fg =correct_fg, bg = '#2f2f2f', font = ("Segoe UI semibold",14))

    global BC_button
    BC_button = Button(available_user_frame, borderwidth=0, activebackground='#2e2e2e', activeforeground="#cccccc", text = "Broadcast Channel", relief = GROOVE, padx = 10, pady=5, font = ("Segoe UI semibold",12), bg = "#1e1e1e", fg = correct_fg, command=lambda:broadcastRaiser(chataction_frame))

    
    chataction_frame.place(relheight=1, relwidth=0.7, relx=1, rely=1, anchor='se')
    chatpanel_frame.place(relheight=0.82, relwidth=1, relx=0,rely=0.51,anchor='w')
    
    message_entry.place(relheight=0.08, relwidth=0.8, relx=0, rely=1, anchor='sw')
    send_button.place(relheight=0.08, relwidth=0.2, relx=1, rely=1, anchor='se')
    client_frame.place(relheight=0.1, relwidth=1, relx=0, rely=0, anchor='nw')
    client_title.place(relheight=0.5, relwidth=0.5, rely=0.5, relx=0.5, anchor=CENTER)
    chataction_frame.tkraise()

    BC_button.pack(fill=X, side=TOP, pady=1)
   
    refresh_client_frame.place(relwidth=1, relheight=0.08, relx=0, rely=1, anchor='sw')
    refresh_client_button.pack(fill=BOTH, expand=1)

    BC_button.tkraise()

    refreshList(my_username)

    print("chat page is visible now")

    
def broadMessage(rec_msg):    
    show_name = rec_msg[0]
    received_msg = rec_msg[1]
    global count_msg

    msg = show_name+" : "+received_msg

    message_list.insert(count_msg, " ["+show_name+"] : "+received_msg)
    message_list.itemconfig(count_msg, bg='#2f2f2f')
    count_msg += 1
    BC_button["borderwidth"] = 2


def generatePrivatekey():
    import random
    minPrime = 2
    maxPrime = 20
    cached_primes = [i for i in range(minPrime,maxPrime) if isprime(i)]

    gp = random.choice([i for i in cached_primes if 2<i<20])
    return gp





def requestReceive(activeUser):
    global list_flag
    global previous_list
    previous_list = []
    list_flag = 0
    while True:
        try:

            message_header = client_socket.recv(1024)
            message_length = int(message_header.decode('utf-8').strip())
            message = client_socket.recv(message_length).decode('utf-8')
            rec_msg = eval(message)
            print("msg", rec_msg)

            if '$LOGIN_INFO~' in rec_msg:
                ret = int(loginGate(rec_msg))
                print("ret", ret)
                if ret == 0:
                    break

            if "$GIVEN_LIST~" in rec_msg:
                list_flag = int(listRequest(rec_msg, my_username, list_flag, previous_list, activeUsers))

            
            if "$GIVEN_MSG~" in rec_msg:
                # senderName, request_uname, request_msg, '$GIVEN_MSG~'
                print("message for ", rec_msg[0], "msg is ", rec_msg[2])
                directMessage(rec_msg, activeUsers)

            if "$GIVEN_BMSG~" in rec_msg:
                #senderName, request_msg, '$GIVEN_BMSG~'
                 print("message from ", rec_msg[0], "msg is ", rec_msg[1])
                 broadMessage(rec_msg)

            if "$DEL_RESPONSE~" in rec_msg:
                disconnectNotification(rec_msg[0], activeUsers)
            
            

             
        except IOError as e:
            if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
                print('Reading error: {}'.format(str(e)))
                sys.exit()


def verifyCredentials():
    global HEADER_LENGTH
    global IP
    global PORT
    global my_socketname
    global my_username
    global client_socket
    global client_list
    global primeNumber
    global G
    global my_publickey
    global my_privatekey
    global entered_uname
    global activeUsers
    activeUsers = []
    

    ######    calculating public key   #############
    # More Modular Exponential (MODP) Diffie-Hellman groups
    # for Internet Key Exchange


    temp = 2**2942
    temp = Decimal(temp)
    temp = temp*Decimal(math.pi)
    temp2 = Decimal(1690314)
    temp3 = Decimal(2**64)
    ####    2**3072 - 2**3008 - 1 + 2**64 * ( (temp) + temp2 ) #####
    primeNumber = Decimal(2**3072 - 2**3008 - 1 + 2**64)*( temp + temp2 )
    primeNumber = int(primeNumber)
    G = 2

    

    my_privatekey = generatePrivatekey()    # private key generated in range 2 to 20
    print("this my private key", my_privatekey)
    my_publickey = G**my_privatekey % primeNumber

    entered_uname = username_entry.get()
    entered_pwd = password_entry.get()

    if entered_uname and entered_pwd:

        HEADER_LENGTH = 1024
        IP = "192.168.1.2"
        PORT = 12000

        #   trying to connect
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((IP, PORT))
        print("connected to the server but not yet verified")
        client_socket.setblocking(False)

        # to check my address
        # my_socketname = client_socket.getsockname()
        # print("laddr : ", my_socketname[1])

        sender_list = []
        sender_list.append(entered_uname)
        sender_list.append(entered_pwd)
        sender_list.append(my_publickey)
        sender_list.append("$LOGIN_REQUEST~")
        print("This is sent for verification ", sender_list)
        sender_list = str(sender_list)

        ####    to send    ############
        sender_list = sender_list.encode('utf-8')
        message_header = f"{len(sender_list):<{HEADER_LENGTH}}".encode('utf-8')

        client_socket.send(message_header + sender_list)
        print("Login request sent. waiting for response")
        
        global t
        Thread(target = requestReceive, args=[activeUsers]).start()
        login_status_frame["text"] = "verify Credentials, Please wait."


    else:
        print("Enter Something")
        login_status_frame["fg"] = incorrect_fg
        login_status_frame["text"] = "Incorrect username or password"
        about_frame.place(relheight=0.65, relwidth=0.575, relx=0.325, rely=0.5, anchor=CENTER)


    #######################################
   
    

login_frame = Frame(root, bg = panel_bg, height = H-250, width = W-350)
login_frame.place(relheight=0.5, relwidth=0.325, relx=0.8, rely=0.5, anchor=CENTER)

login_action_frame = Frame(login_frame, bg='#1e1e1e', width=200)
login_action_frame.pack(expand=1, pady=18)

login_title_frame = Label(login_action_frame, text = "Hey there !", pady = 5, fg = '#cccccc', bg = '#1e1e1e', font = ("Segoe UI",14))
login_title_frame.pack()

login_status_frame = Label(login_action_frame, text = "Enter your Username and Password", pady = 2, fg = correct_fg, bg = '#1e1e1e', font = ("Segoe UI semibold",10))
login_status_frame.pack()

username_frame = Frame(login_action_frame, bg='#1e1e1e')
username_frame.pack(pady=5, expand=1, fill='x')
username_label = Label(username_frame, text = "Username", pady = 10, fg = '#cccccc', bg = '#1e1e1e', font = ("Segoe UI",12))
username_label.pack(side=LEFT, padx=5)
username_entry =Entry(username_frame, state = NORMAL, borderwidth=3, selectbackground = "#1e1e1e", font = ("Segoe UI",12), width=18, relief = FLAT, fg = "#1e1e1e", bg = "#dddddd")
username_entry.pack(side=RIGHT, padx=5)

password_frame = Frame(login_action_frame, height=1, bg='#1e1e1e')
password_frame.pack(expand=1, fill='x')
password_label = Label(password_frame, text = "Password", pady = 10, fg = '#cccccc', bg = '#1e1e1e', font = ("Segoe UI",12))
password_label.pack(side=LEFT, padx=5)
password_entry =Entry(password_frame, show='*', state = NORMAL, borderwidth=3, selectbackground = "#1e1e1e", font = ("Segoe UI",12), width=18, relief = FLAT, fg = "#1e1e1e", bg = "#dddddd")
password_entry.pack(side=RIGHT, padx=5)

login_button = Button(login_action_frame, height=1, text = "Log In", relief = GROOVE, padx = 10, font = ("Segoe UI",14), bg = "#1e1e1e", fg = "#cccccc", command=lambda:verifyCredentials())
login_button.pack(fill='x', padx=5, pady=20)


#################   About chat application  #################

about_frame = Frame(root, bg="#121212")
about_frame.place(relheight=0.65, relwidth=0.575, relx=0.325, rely=0.5, anchor=CENTER)

about_application = "\tDH chat application works on Diffie Hellman key exchange with hashing methods to verify the connection between the users, the messages sent are encrypted and ensured that the cipher text is decrypted only with the secret key generated by the sender and receiver using Diffie Hellman Key Exchange. Thus we ensure users privacy and security with care.\n\nAlways remember that your connection is secured here. Log in via your username and password to connect."

about_title = Label(about_frame, text = "Privacy Matters", pady = 10, fg = '#cccccc', bg = '#121212', font = ("Segoe UI semibold",25))
about_title.pack()

about_application_label = Label(about_frame, text=about_application, fg = '#cccccc', bg = '#121212', font = ("Segoe UI",12), justify=LEFT, wraplength=550)
about_application_label.pack( fill='x')

#########   available users    ##############

def logout_sys():
    root.destroy()
    client_socket.close()
    print("Logged out successfully")
    

userlist_frame = Frame(root, bg='#0d0d0d')
userlist_title = Label(userlist_frame, text = "Available Clients", pady = 10, fg = '#cccccc', bg = '#0d0d0d', font = ("Segoe UI bold",11))

hint_root_frame = Frame(root, bg='#121212')
hint_root_label = Label(hint_root_frame, text = "No users found click Refresh Button.", pady = 10, fg = '#cccccc', bg = '#121212', font = ("Segoe UI",12))

available_user_frame = Frame(userlist_frame, bg = '#0d0d0d')


refresh_client_frame = Frame(userlist_frame, bg='#0d0d0d')
refresh_client_button = Button(refresh_client_frame, borderwidth=0, activebackground='#2e2e2e', activeforeground="#cccccc", height=1, text = "Logout", relief = GROOVE, padx = 10, font = ("Segoe UI semibold",14), bg = "#1e1e1e", fg = incorrect_fg, command=lambda:logout_sys())


root.mainloop()
