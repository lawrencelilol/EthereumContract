/**
 *  Author: Lawrence Li
 *  Last Modified: Feb 23rd, 2022
 *
 *  SigningClientTCP.java provides capabilities to sign messages.
 *  SigningClientTCP has three private members: RSA e,d and n.
 *  These are java BigIntegers.
 *
 *  For signing: the SigningClientTCP object is constructed with RSA
 *  keys (e,d,n). These keys are not created here but are passed in by the caller.
 *  Then, a caller can sign a message - the string returned by the sign
 *  method is evidence that the signer has the associated private key.
 *  After a message is signed, the message and the string may be transmitted
 *  or stored.
 */

import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.net.SocketException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Random;
import java.util.Scanner;

public class SigningClientTCP {

    static BigInteger e; // e is the exponent of the public key
    static BigInteger d; // d is the exponent of the private key
    static BigInteger n; // n is the modulus for both the private and public keys
    // serverPort variable
    static int serverPort;
    // create a client socket
    static Socket clientSocket = null;
    // To check to see if client from the same session
    static int session = 0;
    // id of the client, generated in this program
    static String idStr = "";
    // public key
    static String publicKey = "";

    /** A SigningClientTCP object may be constructed with RSA's e, d, and n.
     *  The holder of the private key (the signer) would call this
     *  constructor. Only d and n are used for signing.
     */
    public SigningClientTCP(BigInteger e, BigInteger d, BigInteger n) {
        this.e = e;
        this.d = d;
        this.n = n;
    }

    public static void main(String args[]) throws Exception {
        System.out.println("The client is running");

        // Let user enter port number
        Scanner reader = new Scanner(System.in);

        System.out.println("Please enter server port: ");
        serverPort = reader.nextInt();
        clientSocket = new Socket("localhost", serverPort);
        System.out.println(" ");

        // user's action choice
        int choice;
        // user input value
        int value;
        // operation result after user's choice of operation
        String res;
        while(true) {
            // list of actions user can choose
            System.out.println("1. Add a value to your sum.");
            System.out.println("2. Subtract a value from your sum.");
            System.out.println("3. Get your sum.");
            System.out.println("4. Exit client");

            // get user's choice of action
            choice = reader.nextInt();
            switch (choice) {
                // if user choose to add
                case 1 -> {
                    System.out.println("Enter value to add: ");
                    // the value entered by the user
                    value = reader.nextInt();
                    // use add helper function to get the result from server
                    res = add(value);
                    if(res.equals("error")) {
                        break;
                    }
                    System.out.println("The result is " + res);
                    System.out.println(" ");
                }
                // if user choose to subtract
                case 2 -> {
                    System.out.println("Enter value to subtract: ");
                    // the value entered by the user
                    value = reader.nextInt();
                    //use min helper function to get the result from server
                    res = min(value);
                    if(res.equals("error")) {
                        break;
                    }
                    System.out.println("The result is " + res);
                    System.out.println(" ");
                }
                // if user choose to get result by a user id
                case 3 -> {
                    //use get helper function to get the result from server
                    res = get();
                    if(res.equals("error")) {
                        break;
                    }
                    System.out.println("The result is " + res);
                    System.out.println(" ");
                }
            }
            // exits the client, but server is still running
            if(choice == 4) {
                System.out.println("Client side quitting. The remote variable server is still running.");
                // Make the session back to 0
                session = 0;
                // close the client socket
                if (clientSocket != null) {
                    clientSocket.close();
                }
                break;
            }
        }
    }

    /**
     * Add helper function
     * @param i value enter by user
     * @return result from server after adding i to the value
     */
    public static String add(int i) throws Exception {
        String res = useServer(i,"add");
        return res;
    }

    /**
     * min helper function
     * @param i value enter by user
     * @return result from server after subtracting i from value
     */
    public static String min(int i) throws Exception {
        String res = useServer(i,"min");
        return res;
    }

    /**
     * get helper function
     * @return user with id's current value from server
     */

    public static String get() throws Exception {
        String res = useServer(0,"get");
        return res;
    }

    /**
     * use this function to connect to server passes in
     * value entered by the user, user's id and types of operation.
     * It also uses RSA to generate the public key and client id
     * @param i value enter by user
     * @param operation type of operation
     * @return the operation result done by the server
     */

    public static String useServer(int i, String operation) throws Exception {
        // initialize value to zero
        String value = "";

        try {
            // reads data from clientSocket
            BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            // write data to clientSocket
            PrintWriter out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream())));

            // Use RSA to sign the data
            String m = RSA(i,operation);
            // send the data to server
            out.println(m);
            out.flush();

            // receive data from server
            String data = in.readLine(); // read a line of data from the stream
            if(data.equals("error")) {
                System.out.println("Error in request!");
            }
            // parse the data to integer
            value = data;
            return value;
        }
        // handle socket exceptions
        catch (SocketException e) {
            System.out.println("Socket: " + e.getMessage());
        }
        // handle general I/O exceptions
        catch (IOException e) {
            System.out.println("IO: " + e.getMessage());
        }
        return value;
    }

    /**
     * Reference: DS Project2 Task 5 RSAExample.java
     *
     *  1. Select at random two large prime numbers p and q.
     *  2. Compute n by the equation n = p * q.
     *  3. Compute phi(n)=  (p - 1) * ( q - 1)
     *  4. Select a small odd integer e that is relatively prime to phi(n).
     *  5. Compute d as the multiplicative inverse of e modulo phi(n). A theorem in
     *      number theory asserts that d exists and is uniquely defined.
     *  6. Publish the pair P = (e,n) as the RSA public key.
     *  7. Keep secret the pair S = (d,n) as the RSA private key.
     *  8. Generate client id
     *  9. Create message = id, the public key (e and n), the operation, the operand.
     *  10. Sign the message: signature = E(h(message),d).
     *  11. Return the combination of message + signature
     *
     * @param i
     * @param operation
     * @return the combination of clear message and signature
     * @throws Exception
     */

    public static String RSA(int i,String operation) throws Exception {

        // create public key and client id once the same session
        if(session == 0) {
            // Used the code from RSAExample.java for Project2Task5
            // Each public and private key consists of an exponent and a modulus
            Random rnd = new Random();

            // Step 1: Generate two large random primes.
            // We use 2048 bits here, the best practice for security is 2048 bits.
            BigInteger p = new BigInteger(2048, 100, rnd);
            BigInteger q = new BigInteger(2048, 100, rnd);

            // Step 2: Compute n by the equation n = p * q.
            n = p.multiply(q);

            // Step 3: Compute phi(n) = (p-1) * (q-1)
            BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

            // Step 4: Select a small odd integer e that is relatively prime to phi(n).
            // By convention the prime 65537 is used as the public exponent.
            e = new BigInteger("65537");

            // Step 5: Compute d as the multiplicative inverse of e modulo phi(n).
            d = e.modInverse(phi);

            // Print the public key to console
            System.out.println("The public key is: ");// Step 6: (e,n) is the RSA public key
            System.out.println("e: " + e);
            System.out.println("n: " + n);
            // line break
            System.out.println(" ");
            // Print the private key to console
            System.out.println("The private key is: ");// Step 7: (d,n) is the RSA private key
            System.out.println("d: " + d);
            System.out.println("n: " + n);

            // convert the e and n to string and concatenate them
            // to get the public key
            publicKey = String.valueOf(e) + String.valueOf(n);
            // hash the public key using SHA-256
            byte[] publicKeyBytes = publicKey.getBytes();
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(publicKeyBytes);
            byte[] publicKeyDigest = md.digest();

            // takes the least significant 20 bytes of the hash
            byte[] messageDigest;
            int len = publicKeyDigest.length;
            messageDigest = Arrays.copyOfRange(publicKeyDigest,len - 20, len);

            // client id created
            BigInteger id = new BigInteger(messageDigest);
            idStr = id.toString();
            // increase the session so the program knows if it is the same client
            session++;
        }

        // Create SigningClientTCP
        SigningClientTCP sov = new SigningClientTCP(e,d,n);

        // make the operand from user's input as a string
        String operand = String.valueOf(i);

        // Combine id, the public key, the operation, and the operand for signature
        String message = idStr  + "," + publicKey + "," + operation + "," + operand;
        String signedVal = sov.sign(message);

        return message + ";" + signedVal;
    }

    /**
     * Signing proceeds as follows:
     * 1) Get the bytes from the string to be signed.
     * 2) Compute a SHA-1 digest of these bytes.
     * 3) Copy these bytes into a byte array that is one byte longer than needed.
     *    The resulting byte array has its extra byte set to zero. This is because
     *    RSA works only on positive numbers. The most significant byte (in the
     *    new byte array) is the 0'th byte. It must be set to zero.
     * 4) Create a BigInteger from the byte array.
     * 5) Encrypt the BigInteger with RSA d and n.
     * 6) Return to the caller a String representation of this BigInteger.
     * @param message a string to be signed
     * @return a string representing a big integer - the encrypted hash.
     * @throws Exception
     */
    public String sign(String message) throws Exception {

        // compute the digest with SHA-256
        byte[] bytesOfMessage = message.getBytes("UTF-8");
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] bigDigest = md.digest(bytesOfMessage);

        // we only want two bytes of the hash for SigningClientTCP
        // we add a 0 byte as the most significant byte to keep
        // the value to be signed non-negative.
        byte[] messageDigest = new byte[bigDigest.length + 1];
        messageDigest[0] = 0;   // most significant set to 0
        System.arraycopy(bigDigest,0,messageDigest,1,bigDigest.length);

        // From the digest, create a BigInteger
        BigInteger m = new BigInteger(messageDigest);

        // encrypt the digest with the private key
        BigInteger c = m.modPow(d, n);

        // return this as a big integer string
        return c.toString();
    }
}

