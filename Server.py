from socket import *
import socket
import sys
from crypto import *
import base64
from register_users import *
from pyDH import *
from cryptography.hazmat.backends import default_backend
from configuration import *
import signal
import time




client_list = {}
buff=4096
users_session_key={}
users_pubkey_dict={}
my_name={}


with open("private_key.pem", "rb") as key_file:
     server_private_key = serialization.load_pem_private_key(key_file.read(),password=None,backend=default_backend())

with open("public_key.pem", "rb") as key_file1:
     server_public_key = serialization.load_pem_public_key(key_file1.read(),backend=default_backend())
crypt=crypto()


reg_user=register_users()

try:
      server_sock=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
     # host=socket.gethostname()
     # host_ip=socket.gethostbyname(host)  #getting server host_ip for cross machine usage
except socket.error:
      print 'Something went wrong, please try again'
      sys.exit(1)

def signal_handler(sig,frame):
        print(' Ok,exiting')
        time.sleep(1)
        os._exit(0)


def server_setup(host_addr):
    try:
        server_sock.bind(host_addr)
        print "Server Initialized "
    except:
        print "The port is already in use, please change to a different port in the configuration.py file"
        sys.exit(1)

def client_details(client_data): #client data might be encrypted or signed

    msg = client_data[0]
    client_ip,client_port=client_data[1]
    client_data=str(msg)


    if client_data.find('SIGN-IN')!=-1:
        try:
                username=msg.split(':,:,:')[0]
                username += "=" * ((4 - len(username) % 4) % 4) # adding padding if data is lost
                encrypted_username=base64.decodestring(username) #decoding username
                username=crypt.rsa_decryption(server_private_key,encrypted_username) #decrypt username

                #check if the user is registered or not
                if(reg_user.creds(username)==1):
                    password=reg_user.credentials[username]

                    salt = os.urandom(16)

                    key=crypt.key_derivation(password,salt)
                    iv=os.urandom(32)
                    challenge_random=os.urandom(32)
                    tag,challenge=crypt.symmetric_encryption(key,iv,challenge_random)
                    Challenge_signature=crypt.sign(server_private_key,challenge)
                    challenge=challenge+':,:,:'+tag+':,:,:'+iv+':,:,:'+salt+':,:,:'+Challenge_signature
                    server_sock.sendto(challenge,((client_ip),client_port))

                    #receive response from client against client

                    client_data = server_sock.recvfrom(buff)



                    client_data=client_data[0]
                    client_data=crypt.rsa_decryption(server_private_key,client_data)

                    used_nonce=str(client_data.split(':,:,:')[4])



                    if client_data.split(':,:,:')[0]==challenge_random and crypt.nonce_check(used_nonce)==1:

                                        client_public_key=client_data.split(':,:,:')[3]
                                        client_pub=serialization.load_pem_public_key(client_public_key, backend=default_backend())
                                        dh_key = pyDH.DiffieHellman()
                                        dh_pubkey = dh_key.gen_public_key()
                                        key=os.urandom(32)
                                        iv=os.urandom(32)
                                        n1=crypt.create_nonce()
                                        n2=crypt.create_nonce()
                                        data_to_encrypt=str(dh_pubkey)+":,:,:"+n1+":,:,:"+n2

                                        tag,dh_pubkey_encrypted=crypt.symmetric_encryption(key,iv,str(data_to_encrypt))
                                        key_encrypted=crypt.rsa_encryption(client_pub,key)

                                        dh_pubkey_to_send=str(dh_pubkey_encrypted)+":,:,:"+str(key_encrypted)+":,:,:"+iv+":,:,:"+tag
                                        server_sock.sendto(dh_pubkey_to_send,((client_ip),client_port))


                                        dh_peer_pub_key_encrypted = server_sock.recvfrom(buff)[0]
                                        dh_peer_pub_key_nonce = crypt.rsa_decryption(server_private_key,dh_peer_pub_key_encrypted)
                                        dh_peer_pub_key=long(dh_peer_pub_key_nonce.split(":,:,:")[0])
                                        n2_received=dh_peer_pub_key_nonce.split(":,:,:")[1]

                                        if n2==n2_received:

                                          dh_sharedkey = dh_key.gen_shared_key(dh_peer_pub_key)
                                          client_list[username]=client_data[1]
                                          users_session_key[username]=dh_sharedkey
                                          users_pubkey_dict[username]=client_public_key
                                          client_list[username]=str(client_ip)+':'+str(client_port)
                                          my_name[client_port]=username
                                        else:
                                           server_sock.sendto("hack",((client_ip),client_port))



                    else:
                                        #nonce=crypt.create_nonce()
                                        #server_sock.sendto(nonce,((client_ip),client_port))
                       raise Exception



                else:
                    message = "no_user"
                    sig= crypt.sign(server_private_key,message)
                    message = message+":,:,:"+sig
                    server_sock.sendto(message,((client_ip),client_port))





                                #elif client_list.has_key(username):
                                #     server_sock.sendto("+> User already Signed In", ((client_ip,client_port)))

                                #elif client_list.has_key(username)==False:
                                 #   client_list[username]=str(client_ip)+':'+str(client_port)
                                  #  server_sock.sendto('success',((client_ip),client_port))
                                   # return




        except:
           try:
                del client_list[username]
                del users_session_key[username]
                del users_pubkey_dict[username]

           except:
                return




    elif client_data.find('list')!=-1:

        message=base64.decodestring(msg)
        message=crypt.rsa_decryption(server_private_key,message)

        username = message.split(":,:,:")[0]

        if client_list.has_key(username):

          list_to_send = list(set(client_list.keys()) - set([username]))
          list_name=''
          for i in list_to_send[:]:
              list_name=list_name+' '+i

          iv = os.urandom(32)
          key=str(users_session_key[username])[:len(str(users_session_key[username]))/2]
          tag,encrypt_list_name=crypt.symmetric_encryption(key,iv,list_name)
          encrypt_list_name=str(encrypt_list_name)+":,:,:"+iv+":,:,:"+tag

          server_sock.sendto(encrypt_list_name,((client_ip),client_port))
          #print str(type(client_ip)) + str(type(client_port))
          return


    elif client_data.find('send')!=-1:

        try:

          n1=client_data.split(":,:,:")[2]
          if crypt.nonce_check(n1)==1:
             encrypted_username=client_data.split(":,:,:")[0]
             iv=client_data.split(":,:,:")[1]

             tag = client_data.split(":,:,:")[3]
             encrypted_my_username=client_data.split(":,:,:")[4]
             my_username=crypt.rsa_decryption(server_private_key,encrypted_my_username)
             #my_username=my_name[client_port]
             #my_username = client_data.split(":,:,:")[4]
             key=str(users_session_key[my_username])[:len(str(users_session_key[my_username]))/2]
             peer_username=crypt.symmetric_decryption(key,iv,encrypted_username,tag)
             user_info_to_send= client_list[my_username]


             for_peer_info=client_list[my_username]+":,:,:"+users_pubkey_dict[my_username]
             key=str(users_session_key[peer_username])[:len(str(users_session_key[peer_username]))/2]
             iv=os.urandom(32)
             n2=uuid.uuid4().hex
             shared_peer_key=os.urandom(32)

             for_peer_info=for_peer_info+":,:,:"+shared_peer_key

             peer_info_to_send = client_list[peer_username]
             peer_pub = users_pubkey_dict[peer_username]


             tag,encrypted_peer_info=crypt.symmetric_encryption(key,iv,for_peer_info)
             message=encrypted_peer_info+":,:,:"+iv+":,:,:"+tag

             final_message=n1+":,:,:"+n2+":,:,:"+peer_pub+":,:,:"+peer_info_to_send+":,:,:"+message+":,:,:"+shared_peer_key
             key=str(users_session_key[my_username])[:len(str(users_session_key[my_username]))/2]
             iv=os.urandom(32)


             tag,final_message_encrypted= crypt.symmetric_encryption(key,iv,final_message)
             final_final=final_message_encrypted+":,:,:"+tag+":,:,:"+iv

             #final_message_encoded=base64.encodestring(str(final_final))
             server_sock.sendto(final_final, ((client_ip),client_port))




          else:

              server_sock.sendto("+> hack", ((client_ip),client_port)) #need to handle this **********
        except:
       #   server_sock.sendto("+> Username not present",((client_ip),client_port))

          return

    elif client_data.find('logout'):

        encrypted_data = client_data.split(":,:,:")[0]
        message = crypt.rsa_decryption(server_private_key,encrypted_data)
        user=message.split(":,:,:")[0]
        nonce=message.split(":,:,:")[1]
        if crypt.nonce_check(nonce) == 1:
            nonce=crypt.create_nonce()
            shared_key=users_session_key[user]
            iv = os.urandom(32)
            key=str(users_session_key[user])[:len(str(users_session_key[user]))/2]
            tag,encrypt_nonce = crypt.symmetric_encryption(key,iv,nonce)
            send = encrypt_nonce+":,:,:"+iv+":,:,:"+tag
            server_sock.sendto(send, ((client_ip),client_port))
            del client_list[user]
            del users_session_key[user]
            del users_pubkey_dict[user]



signal.signal(signal.SIGINT, signal_handler)


def main():

   try:
        config = configuration()
        host_ip=config.ip
        port=config.port

        #print 'Server Initialized...'
   except:
        print "Configuration error"
        sys.exit(1)


   host_addr=host_ip,port
   server_setup(host_addr)


   while 1:
              client_data = server_sock.recvfrom(buff)
              client_details(client_data)



main()
