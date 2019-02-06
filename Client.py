from socket import *
import socket
import sys
import threading
import uuid
from crypto import *
import base64
from pyDH import *
from configuration import *
import time
import signal


client_buff=4096
prompt=''
user_session={}
my_username={}
server_addr = {}


crypt = crypto()
with open("public_key.pem", "rb") as key_file:
    server_pub_key = serialization.load_pem_public_key(key_file.read(),backend=default_backend())


client_pub,client_priv=crypt.rsa_key_pair()


def signal_handler(sig,frame):       #if control ^c is detected, safely log out
        username = my_username["0"]
        nonce = crypt.create_nonce()
        message = username +":,:,:"+ nonce
        client_socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        encrypted = crypt.rsa_encryption(server_pub_key,message)
        final_message= encrypted+":,:,:"+"logout"
        client_socket.sendto(final_message,(server_addr["0"]))
        received = client_socket.recvfrom(client_buff)[0]
        nonce_encrypted = received.split(":,:,:")[0]
        iv = received.split(":,:,:")[1]
        tag = received.split(":,:,:")[2]
        shared_key = str(user_session[username])[:len(str(user_session[username]))/2]
        nonce = crypt.symmetric_decryption(shared_key,iv,nonce_encrypted,tag)
        if crypt.nonce_check(nonce) == 1:
            print "<Logged Out, the Client module will shutdown now>"
            time.sleep(1)
            os._exit(0)



def client_send_message_thread():  #Thread for message prompt

        client_socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM) #registering client socket as datagram
        username_client= my_username["0"]
        config=configuration()

        server_ip = config.ip
        server_port = config.port
        server_address = server_ip,server_port

        while 1:

            prompt=raw_input('+>')


            if prompt.find('list') !=-1 and prompt.find('list')==0:# if list command is encountered

                nonce=crypt.create_nonce()
                username_client_send = crypt.rsa_encryption(server_pub_key,username_client)
                username_client_encoded=base64.encodestring(username_client_send)



                message=username_client_encoded+":,:,:"+str(nonce)+":,:,:"+"list"
                client_socket.sendto(message,(server_address))

                server_data1=client_socket.recvfrom(client_buff)[0]
                encrypted_data=server_data1.split(":,:,:")[0]
                iv=server_data1.split(":,:,:")[1]
                tag=server_data1.split(":,:,:")[2]
                key=str(user_session[username_client])[:len(str(user_session[username_client]))/2]

                server_data1=crypt.symmetric_decryption(key,iv,encrypted_data,tag)


                print '<- Signed In Users: '+server_data1



            elif prompt.find('send')!=-1 and prompt.find('send')==0:  #if send command is encountered
                 try:
                   get_client_username= prompt.split(' ')[1]
                   get_client_details=prompt.split(' ')[1:]

                 except:
                     print "No username entered, please use the format: " \
                           "send <username> <message> to send messages"
                     continue

                 if get_client_username:

                     encrypted_username_client=crypt.rsa_encryption(server_pub_key,username_client)
                     get_client_message= prompt.split(' ')[2:]


                     #Grab the symmetric key client_server and IV
                     #pass encrypted initial message to server
                     key=str(user_session[username_client])[:len(str(user_session[username_client]))/2]
                     iv=os.urandom(32)
                     tag,encrypted_client_details=crypt.symmetric_encryption(key,iv,str(get_client_username))
                     n1=uuid.uuid4().hex


                     get_peer_information=encrypted_client_details+":,:,:"+iv+":,:,:"+n1+":,:,:"+tag+":,:,:"\
                                          +encrypted_username_client+":,:,:"+"send"


                     client_socket.sendto(get_peer_information,(server_address))

                     try:
                       client_socket.settimeout(3)
                       get_client_details_encoded= client_socket.recvfrom(client_buff) #reusing variable for receiver details
                       client_socket.settimeout(None)
                     except:
                         print "Either the user is not logged-in or not registered"
                         continue

                     get_client_details_decoded=get_client_details_encoded[0]

                     encrypted_message=get_client_details_decoded.split(":,:,:")[0]

                     tag = get_client_details_decoded.split(":,:,:")[1]
                     iv = get_client_details_decoded.split(":,:,:")[2]




                     get_peer_info = crypt.symmetric_decryption(key,iv,encrypted_message,tag)

                     n1_received=get_peer_info.split(":,:,:")[0]
                     n2=get_peer_info.split(":,:,:")[1]
                     peer_pub=get_peer_info.split(":,:,:")[2]
                     peer_info_to_send=get_peer_info.split(":,:,:")[3]
                     message=get_peer_info.split(":,:,:")[4]
                     iv_peer=get_peer_info.split(":,:,:")[5]
                     tag_peer=get_peer_info.split(":,:,:")[6]
                     shared_peer_key=get_peer_info.split(":,:,:")[7]

                     get_client_message = " ".join(str(x) for x in get_client_message)

                     n3=crypt.create_nonce()
                     get_client_message= get_client_message+":,:,:"+str(username_client)+":,:,:"+n3
                     iv= os.urandom(32)
                     tag,my_message_encrypted = crypt.symmetric_encryption(shared_peer_key,iv,get_client_message)




                     if n1!=n1 and crypt.nonce_check(n2)==0:
                         print "Hack Detected, shutting down"
                         os._exit(0)

                     else:
                         peer_ip=peer_info_to_send.split(':')[0]
                         peer_port=peer_info_to_send.split(':')[1]
                         peer_pub_key=serialization.load_pem_public_key(peer_pub, backend=default_backend())
                         encrypt_key_for_peer=crypt.rsa_encryption(peer_pub_key,shared_peer_key)
                         finale=my_message_encrypted+":,:,:"+iv+":,:,:"+tag+":,:,:"+encrypt_key_for_peer



                         client_socket.sendto(finale,(peer_ip,int(peer_port)))  #sending message to peer client
                         client_socket.settimeout(None)

                 else:
                     print "Please enter the username you want to send message to. Use" \
                           "the format Send <username> <message> to send the message"



                    #except:
                    # print 'Wrong Username. Please check the username via list command and send the message in the format:'\
                     #      'send <username> <message>'



            elif (prompt.find('logout')!=-1 and prompt.find('logout')==0) or (prompt.find('exit')!=-1 and prompt.find('exit')==0) \
                    or (prompt.find('quit')!=-1 and prompt.find('quit')==0):

                username = my_username["0"]
                nonce = crypt.create_nonce()
                message = username +":,:,:"+ nonce

                encrypted = crypt.rsa_encryption(server_pub_key,message)
                final_message= encrypted+":,:,:"+"logout"
                client_socket.sendto(final_message,(server_address))
                received = client_socket.recvfrom(client_buff)[0]
                nonce_encrypted = received.split(":,:,:")[0]
                iv = received.split(":,:,:")[1]
                tag = received.split(":,:,:")[2]
                shared_key = str(user_session[username])[:len(str(user_session[username]))/2]
                nonce = crypt.symmetric_decryption(shared_key,iv,nonce_encrypted,tag)
                if crypt.nonce_check(nonce) == 1:
                    print "<Logged Out, the Client module will shutdown now>"
                    time.sleep(1)
                    os._exit(1)



            else:
                print 'Commands Supported:\nlist - to get the complete list of users connected \n '\
                      'send <username> <message> - to send peers your message\n' \
                      'logout, exit or quit to safely logout'

            #signal.signal(signal.SIGINT, signal_handler)




def main():
    try:
          config=configuration()
          username_client= raw_input("Please enter your username: ")
          passwd=raw_input("Please enter your password: ")
          server_ip = config.ip
          server_port = config.port
    except:
       print 'check server configuration on configuration.py'


    try:
       client_socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
       client_name = socket.gethostname()
       client_ip = socket.gethostbyname(client_name)
    except:
       print 'Its not you, it\'s us, please try again'


    server_address = server_ip,server_port

    server_addr["0"] = server_address

    my_username["0"]=username_client

    username_encrypted=crypt.rsa_encryption(server_pub_key,username_client)
    username_client_encoded=base64.encodestring(username_encrypted)



    message=username_client_encoded+':,:,:'+'SIGN-IN'   #sending SIGN-IN message to register user on the server

    #username to be sent to server for authentication, encrypted with public key of server

    client_socket.sendto(message,((server_address)))

    try:
      client_socket.settimeout(4)
      server_data = client_socket.recvfrom(client_buff)
      client_socket.settimeout(None)
    except timeout:
        print "Looks like the server is unreachable or offline,please try again"
        os._exit(1)

    serv_string=str(server_data[0])

    if serv_string.find('no_user')!=-1:
        sig = serv_string.split(":,:,:")[1]
        try:
          crypt.verify(server_pub_key,sig,"no_user")
          print "incorrect username or password, please log back in with the correct credentials"
          time.sleep(1)
          os._exit(0)
        except:
           return

    challenge_from_server=server_data[0]
    challenge=challenge_from_server.split(':,:,:')[0]
    tag=challenge_from_server.split(':,:,:')[1]
    iv=challenge_from_server.split(':,:,:')[2]
    salt=challenge_from_server.split(':,:,:')[3]
    challenge_sig=challenge_from_server.split(':,:,:')[4]

    try:
      crypt.verify(server_pub_key,challenge_sig,challenge)     #verifying that the challenge came from the server
    except:
        print "signature forged, shutting down"
        os._exit(0)

    passwd=crypt.key_derivation(passwd,salt)       #deriving key from the user supplied password

    try:

      response=crypt.symmetric_decryption(passwd,iv,challenge,tag)
    except:
        print "incorrect username or password, please log back in with the correct credentials"
        response=os.urandom(32)
        salt_for_passwd=os.urandom(2)
        passwd=salt_for_passwd+passwd
        digest=crypt.hash(passwd)
        client_pub_bytes=crypt.key_conversion_bytes(client_pub)
        Nonce = uuid.uuid4().hex
        complete_response=response+":,:,:"+salt_for_passwd+":,:,:"+str(digest)+":,:,:"+client_pub_bytes+":,:,:"+Nonce
        complete_response_encrypted=crypt.rsa_encryption(server_pub_key,complete_response)
        client_socket.sendto(complete_response_encrypted,(server_address)) # sending wrong response to server if password is incorrect
        time.sleep(1)
        os._exit(0)


    #construct response for the server
    salt_for_passwd=os.urandom(2)
    passwd=salt_for_passwd+passwd
    digest=crypt.hash(passwd)



    #client_pub_load=crypt.public_key_load(client_pub) # for serializing public key of client
    client_pub_bytes=crypt.key_conversion_bytes(client_pub)

    Nonce = uuid.uuid4().hex

    complete_response=response+":,:,:"+salt_for_passwd+":,:,:"+str(digest)+":,:,:"+client_pub_bytes+":,:,:"+Nonce


    complete_response_encrypted=crypt.rsa_encryption(server_pub_key,complete_response)
    client_socket.sendto(complete_response_encrypted,(server_address))

    dh_key = pyDH.DiffieHellman()
    dh_pubkey = dh_key.gen_public_key()


    try:
      client_socket.settimeout(2)
      dh_peer_pub_key_encrypted = client_socket.recvfrom(client_buff)[0]
      client_socket.settimeout(None)
    except:
        print "incorrect username or password, please log back in with the correct credentials"

    if(dh_peer_pub_key_encrypted!="failure"):

      dh_encrypted_key=dh_peer_pub_key_encrypted.split(':,:,:')[0]
      key_encrypted=dh_peer_pub_key_encrypted.split(':,:,:')[1]
      iv= dh_peer_pub_key_encrypted.split(':,:,:')[2]
      tag= dh_peer_pub_key_encrypted.split(':,:,:')[3]


      get_symmtric_key=crypt.rsa_decryption(client_priv,key_encrypted)

      get_shared_key_n1_n2=crypt.symmetric_decryption(get_symmtric_key,iv,dh_encrypted_key,tag)
      get_shared_key=long(get_shared_key_n1_n2.split(":,:,:")[0])
      n1=get_shared_key_n1_n2.split(":,:,:")[1]
      n2=get_shared_key_n1_n2.split(":,:,:")[2]

      if crypt.nonce_check(n1)==0 or crypt.nonce_check(n2)==0:
          print "Hack detected, shutting down"
          os._exit(0)

      else:
          dh_pub_nonce = str(dh_pubkey)+":,:,:"+n2
          dh_pubkey_encrypt=crypt.rsa_encryption(server_pub_key,dh_pub_nonce)
          client_socket.sendto(dh_pubkey_encrypt,(server_address))


      dh_sharedkey = dh_key.gen_shared_key(long(get_shared_key))
      user_session[username_client]=dh_sharedkey

    else:
        print "Hack detected, shutting down, Please login again"
        os._exit(0)

    client_send_thread=threading.Thread(target=client_send_message_thread) #spawning a thread to send command
    client_send_thread.start()

    while 1:            #for messages to peer
            try:

                peer_message=client_socket.recvfrom(client_buff)[0]
                encrypted_msg= peer_message.split(":,:,:")[0]
                encrypted_key = peer_message.split(":,:,:")[3]
                iv=peer_message.split(":,:,:")[1]
                tag=peer_message.split(":,:,:")[2]

                shared_peer_key=crypt.rsa_decryption(client_priv,encrypted_key)


                decrypted_message= crypt.symmetric_decryption(shared_peer_key,iv,encrypted_msg,tag)

                n3=decrypted_message.split(":,:,:")[2]
                if crypt.nonce_check(n3)==1:
                    message=decrypted_message.split(":,:,:")[0]
                    user_who_sent_it = decrypted_message.split(":,:,:")[1]

                else:
                    print "hack detected, Shutting down"
                    sys.exit(1)



                print '\n<-' + ' <From '+user_who_sent_it+'>: '+message
                #final message to print
                sys.stdout.write('+>')
                sys.stdout.flush()
            except:
                continue # so that it goes on an endless listening loop
signal.signal(signal.SIGINT, signal_handler)




main()
