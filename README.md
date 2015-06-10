# 64-Bit-Encrypted-Chat-System
Three main systems:
1. Client
2. Server
3. Key server

User input text message will be encrypted using DES block cipher and CBC block cipher mode.
Key server will be used to exchange secret keys/ private keys and authentication key between client and server.
Once the connection is authenticated after verification, client and server can communicate with each other.
