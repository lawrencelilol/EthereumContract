# Ethereum Contract Signing and Verifying Using TCP

This project is modeled like the way an Ethereum blockchain client signs requests.

1. The client will be interactive and menu driven. It will transmit add or subtract or get requests to the server, along with the ID computed in 3 below, and provide an option to exit.

2. We want to send signed request from the client. Each time the client program runs, it will create new RSA public and private keys and display these keys to the user. See the RSAExample.java program below for guidance on how to build these keys. After the client program creates and displays these keys, it interacts with the user and the server.

3. The client's ID will be formed by taking the least significant 20 bytes of the hash of the client's public key. As in Bitcoin or Ethereum, the user's ID is derived from the public key.

4. The client will also transmit its public key with each request. Again, note that this key is a combination of e and n. These values will be transmitted in the clear and will be used by the server to verify the signature.

5. Finally, the client will sign each request. So, by using its private key (d and n), the client will encrypt the hash of the message it sends to the server. The signature will be added to each request. It is very important that the big integer created with the hash (before signing) is positive. RSA does not work with negative integers. 

6. The server will make two checks before servicing any client request. First, does the public key (included with each request) hash to the ID (also provided with each request)? Second, is the request properly signed? If both of these are true, the request is carried out on behalf of the client. The server will add, subtract or get. Otherwise, the server returns the message "Error in request".

7. We will use SHA-256 for our hash function h().


Reference: https://github.com/CMU-Heinz-95702/Project-2-Client-Server
