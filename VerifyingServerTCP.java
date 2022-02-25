/**
 *  Author: Lawrence Li
 *  Last Modified: Feb 23rd, 2022
 *
 *  VerifyingServerTCP.java provides capabilities to verify messages sent
 *  from SigningClientTCP.java. If the message sent by the client has a valid
 *  signature and the public key matches the client id, then the server will
 *  provide service to the client's request. If not, it will return an error
 *  message to the client.
 *
 *  VerifyingServerTCP has two private members: RSA e and n.
 *  These are java BigIntegers.
 *
 *  For verification: the object is constructed with keys (e and n). The verify
 *  method is called with two parameters - the string to be checked and the
 *  evidence that this string was indeed manipulated by code with access to the
 *  private key d.
 *
 */


import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Map;
import java.util.Scanner;
import java.util.TreeMap;

public class VerifyingServerTCP {

    private BigInteger e,n;

    /** For verifying, a SignOrVerify object may be constructed
     *   with a RSA's e and n. Only e and n are used for signature verification.
     */
    public VerifyingServerTCP(BigInteger e, BigInteger n) {
        this.e = e;
        this.n = n;
    }


    public static void main(String args[]) throws Exception {

        // initialize a Treemap to store user's id and value
        // User's id is the key of the map and the value
        // is the cumulative results of all the user's action.
        Map<String,Integer> userData = new TreeMap<>();

        // create a clientSocket
        Socket clientSocket = null;

        // Server prompt the user for the port number
        // that the server is supposed to listen on
        Scanner reader = new Scanner(System.in);
        System.out.println("Enter port number: ");
        int serverPort = reader.nextInt();
        System.out.println("Port " + serverPort + " is using");
        System.out.println("Server started");

        try{
            // create a new server socket
            ServerSocket listenSocket = new ServerSocket(serverPort);

            // server keeps running forever
            while(true){
                /*
                 * waits for a new connection request from a client.
                 * When the request is received, "accept" it, and the rest
                 * the tcp protocol handshake will then take place, making
                 * the socket ready for reading and writing.
                 */
                clientSocket = listenSocket.accept();

                // If we get here, then we are now connected to a client.
                Scanner in = new Scanner(clientSocket.getInputStream());
                // Set up "out" to write to the client socket
                PrintWriter out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream())));

                // read each line from socket, do the operation and send the result
                // back to the client
                while(in.hasNextLine()) {
                    // receive data from client
                    String data = in.nextLine();
                    // break the data into user's input value, user id and type of operation
                    String[] dataArray = data.split(";");

                    String clearVal = dataArray[0];
                    String signedVal = dataArray[1];

                    String[] m = clearVal.split(",");
                    String id = m[0];
                    String operation = m[2];
                    String operand = m[3];
                    int value = Integer.parseInt(operand);

                    // Checks two things:
                    // 1. Does the public key hashes to client' id correctly?
                    // 2. Is the request properly signed?
                    // If both are true, the server will do the operation for the client
                    // else if one of the above condition is false,
                    // the server will return an error message to client
                    if(!checkBeforeService(clearVal,signedVal)) {
                        System.out.println("Error in request");
                        out.println("error");
                        out.flush();
                    } else {
                        // do addition
                        if(clearVal.contains("add")) {
                            if(userData.containsKey(id)){
                                System.out.println("user with id: " + id +" adding " + value + " to " +  userData.get(id));
                                userData.put(id, userData.get(id) + value);
                            } else {
                                System.out.println("user with id: " + id +" adding " + value + " to " + 0);
                                userData.put(id, value);
                            }
                        }

                        // do subtraction
                        if(clearVal.contains("min")) {
                            if(userData.containsKey(id)){
                                System.out.println("user with id: " + id +" subtracting " + value + " to " +  userData.get(id));
                                userData.put(id, userData.get(id) - value);
                            } else {
                                System.out.println("user with id: " + id +" subtracting " + value + " to " + 0);
                                userData.put(id, -value);
                            }
                        }

                        // get value for the user with id
                        if (clearVal.contains("get")) {
                            System.out.println("user with id: " + id +" getting " +  userData.get(id));
                        }

                        int curVal = userData.get(id);
                        System.out.println("Returning " + curVal +" as the result of "+ operation +" to client");
                        System.out.println(" ");

                        //echo back to client socket
                        out.println(curVal);
                        out.flush();
                    }
                }
            }
        }
        // handle socket exceptions
        catch (SocketException e) {
            System.out.println("Socket: " + e.getMessage());
        }
        // handle general I/O exceptions
        catch (IOException e) {
            System.out.println("IO: " + e.getMessage());
        } finally {
            // always close the socket
            if(clientSocket != null) {
                try {
                    clientSocket.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    /**
     * Verifying proceeds as follows:
     * 1) Decrypt the encryptedHash to compute a decryptedHash
     * 2) Hash the messageToCheck using SHA-256 (be sure to handle
     *    the extra byte as described in the signing method.)
     * 3) If this new hash is equal to the decryptedHash, return true else false.
     *
     * @param messageToCheck  a normal string that needs to be verified.
     * @param encryptedHashStr integer string - possible evidence attesting to its origin.
     * @return true or false depending on whether the verification was a success
     * @throws Exception
     */
    public boolean verify(String messageToCheck, String encryptedHashStr) throws Exception  {

        // Take the encrypted string and make it a big integer
        BigInteger encryptedHash = new BigInteger(encryptedHashStr);
        // Decrypt it
        BigInteger decryptedHash = encryptedHash.modPow(e, n);

        // Get the bytes from messageToCheck
        byte[] bytesOfMessageToCheck = messageToCheck.getBytes("UTF-8");

        // compute the digest of the message with SHA-256
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        byte[] messageToCheckDigest = md.digest(bytesOfMessageToCheck);

        // messageToCheckDigest is a full SHA-256 digest
        // take two bytes from SHA-256 and add a zero byte
        byte[] extraByte = new byte[messageToCheckDigest.length + 1];
        extraByte[0] = 0;
        System.arraycopy(messageToCheckDigest,0,extraByte,1,messageToCheckDigest.length);

        // Make it a big int
        BigInteger bigIntegerToCheck = new BigInteger(extraByte);

        // inform the client on how the two compare
        if(bigIntegerToCheck.compareTo(decryptedHash) == 0) {
            return true;
        }
        else {
            return false;
        }
    }

    /**
     * The server will make two checks before servicing any client request.
     * First, does the public key hash to the ID?
     * Second, is the request properly signed?
     * If both of these are true, the request is carried out on behalf of the client
     * @return true
     */
    public static boolean checkBeforeService(String message, String signedVal) throws Exception {

        // split the clear text into string of arrays
        String[] data = message.split(",");

        // get the client's id
        String id = data[0];
        // get the public key
        String publicKey = data[1];

        // First check if the public key hash to ID

        // change public key to byte array
        byte[] publicKeyBytes = publicKey.getBytes();
        // hashing the key to SHA-256
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(publicKeyBytes);
        byte[] publicKeyDigest = md.digest();

        // takes the least significant 20 bytes of the hash
        byte[] messageDigest;
        int len = publicKeyDigest.length;
        messageDigest = Arrays.copyOfRange(publicKeyDigest,len - 20, len);

        // change least significant 20 bytes of the hashes to BigInteger
        BigInteger publicKeyHash = new BigInteger(messageDigest);

        // if the public key does not hash to ID return false;
        if(!publicKeyHash.toString().equals(id)) {
            System.out.println("The public key does not hash to the ID");
            return false;
        }

        // Second, Check if the request is properly signed
        BigInteger e = new BigInteger("65537");

        // get n from the request
        String nStr = publicKey.substring(5);
        // print the public key
        System.out.println("public key: ");
        System.out.println("e: " + e);
        System.out.println("n: " + nStr);
        System.out.println(" ");

        BigInteger n = new BigInteger(nStr);

        // create verify signature
        VerifyingServerTCP verifySig = new VerifyingServerTCP(e,n);
        // verify the signature, if the signature does not match,
        // it will return false
        if(!verifySig.verify(message,signedVal)) {
            System.out.println("Invalid Signature");
            return false;
        } else {
            System.out.println("Valid Signature");
        }
        return true;
    }
}
