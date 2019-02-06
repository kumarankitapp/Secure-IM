 ____                             ___           _              _            #
/ ___|  ___  ___ _   _ _ __ ___  |_ _|_ __  ___| |_ __ _ _ __ | |_          #
\___ \ / _ \/ __| | | | '__/ _ \  | || '_ \/ __| __/ _` | '_ \| __|         #
 ___) |  __/ (__| |_| | | |  __/  | || | | \__ \ || (_| | | | | |_          #
|____/ \___|\___|\__,_|_|  \___| |___|_| |_|___/\__\__,_|_| |_|\__|         #
                                                                            #
 __  __                                                                     #
|  \/  | ___  ___ ___  ___ _ __   __ _  ___ _ __                            #
| |\/| |/ _ \/ __/ __|/ _ \ '_ \ / _` |/ _ \ '__|                           #
| |  | |  __/\__ \__ \  __/ | | | (_| |  __/ |                              #
|_|  |_|\___||___/___/\___|_| |_|\__, |\___|_|                              #
                                 |___/                                      #
#############################################################################

- Ankit Kumar


Requirements:

This app is built on python 2.7 and uses pyDH library to implement diffie-hellman key exchange. Please Install the library first, using: pip install pyDH

#############################################################################


First Things First:

1.The configuration.py file contains the server IP and Port address that needs 
  to be manually set for the client to get connected and exchange secure messages.

2.The register_users.py file contains the pre registered usernames and password.
  Feel free to add users to the file before firing up the server, or check the 
  default usernames and passwords for using the service.This is only accessible
  by the backend server and the clients cannot control this file.

  Here is the list of registered users:
  username      password
  ankit         password
  rucha         rucha
  root          toor
  admin         12345
  test 		9999
  administrator 0000


3.I would like to think that it is a very secure messenger, but there surely are
  a couple of ways to hack it (That i could find). Most of them are DOS attacks.
  Please report any interesting hacks that you might find at: kumar.ank@husky.neu.edu

4.The Server and Client modules respond to most of the exceptions, be patient for a 
  couple of seconds for it to respond in case of an exception. If it doesn't, exit 
  app with ctrl ^z and restart.

5.Each time a wrong username or password is entered, the client shuts down and you 
  need to restart it (only the client app). Check usage below.

##############################################################################

Usage:

fire up the server by using the command: python Server.py first, then start the 
clients using: python Client.py. On startup, the client app asks for username and 
password to authenticate itself, following which you can send messages to other
connected clients.

It has support for the following commands on successful authentication:

list -> give the list of users currently online

send -> to send messages to online users. Usage: send <username> <message>

logout , exit , quit -> to logout and remove user from currently active user's
                        list

Note: You can press control ^c to logout as well.

To shutdown the gracefully shutdown the server use control ^c, as it allows 
reusability of the current port. Using ctrl ^z will require you to change the
socket in the configuration.py file.


##############################################################################
Disclaimer:

This app is end to end secure, so the server cannot see any message exchanges 
between the clients, but NSA sure can track your IP. Use it at your own 
discretion. 
Have fun and Happy Hacking!






