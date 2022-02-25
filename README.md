# Ethereum Contract

This project is modeled after the way an Ethereum blockchain client signs requests.

1. The client will be interactive and menu driven. It will transmit add or subtract or get requests to the server, along with the ID computed in 3 below, and provide an option to exit.

2. We want to send signed request from the client. Each time the client program runs, it will create new RSA public and private keys and display these keys to the user. See the RSAExample.java program below for guidance on how to build these keys. It is fine to use the code that you find in RSAExample.java (with citations, of course). After the client program creates and displays these keys, it interacts with the user and the server.

3. The client's ID will be formed by taking the least significant 20 bytes of the hash of the client's public key. Note: an RSA public key is the pair e and n. Prior to hashing, you will combine these two integers with concatenation. Unlike in Task 4, we are no longer prompting the user to enter the ID – the ID is computed in the client code. As in Bitcoin or Ethereum, the user's ID is derived from the public key.

4. The client will also transmit its public key with each request. Again, note that this key is a combination of e and n. These values will be transmitted in the clear and will be used by the server to verify the signature.

5. Finally, the client will sign each request. So, by using its private key (d and n), the client will encrypt the hash of the message it sends to the server. The signature will be added to each request. It is very important that the big integer created with the hash (before signing) is positive. RSA does not work with negative integers. See details in the code of ShortMessageSign.java and ShortMessageVerify.java below. You may use this code if cited.

6. The server will make two checks before servicing any client request. First, does the public key (included with each request) hash to the ID (also provided with each request)? Second, is the request properly signed? If both of these are true, the request is carried out on behalf of the client. The server will add, subtract or get. Otherwise, the server returns the message "Error in request".

7. By studying ShortMessageVerify.java and ShortMessageSign.java you will know how to compute a signature. Your solution, however, will not use the short message approach as exemplified there. Note that we are not using any Java crypto API's that abstract away the details of signing.

8. We will use SHA-256 for our hash function h().
