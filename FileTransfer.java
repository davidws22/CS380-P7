// ============================================================================
// file: FileTransfer.java
// ============================================================================
// Programmer: David Shin
// Date: 11/28/2017
// Class: CS 380 ("Computer Networks")
// Time: TR 3:00 - 4:50pm
// Instructor: Mr. Davarpanah
// Project : 7
//
// Description: This project implements an encrypted file transfer program.
//    It will operate as either a server or client depending on its command-
//    line arguments. We use serialized Java objects to communicate back and
//    forth between the server and client. We use Java Cryptography Extension
//    to perform the encryption.
//
// ============================================================================
import java.io.*;
import java.util.*;
import java.util.zip.CRC32;
import java.nio.file.*;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.net.*;
import javax.crypto.*;

public class FileTransfer
{
    public static void main(String [] args) throws Exception
    {
	if(args[0].equals("makekeys"))
	{
	    GenKeyPair();
	}
	else if(args[0].equals("server"))
	{
	    String privateKey = args[1];
	    String port = args[2];
	    server(privateKey, port);
	}
	else if(args[0].equals("client"))
	{
	    String publicKey = args[1];
	    String host = args[2];
	    String port = args[3];
	    client(publicKey, host, port);
	}
	else
	{
	    System.out.println("Invalid command line argument");
	}
    }

    //method to generate private and public keys and stores them in private.bin and public.bin, respectively
    private static void GenKeyPair()
    {
	try {
	    KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
	    gen.initialize(4096);
	    KeyPair keyPair = gen.genKeyPair();
	    PrivateKey privateKey = keyPair.getPrivate();
	    PublicKey publicKey = keyPair.getPublic();
	    try (ObjectOutputStream oos = new ObjectOutputStream(
								 new FileOutputStream(new File("public.bin")))) {
		oos.writeObject(publicKey);
	    }
	    try (ObjectOutputStream oos = new ObjectOutputStream(
								 new FileOutputStream(new File("private.bin")))) {
		oos.writeObject(privateKey);
	    }
	} catch (Exception e) {
	    e.printStackTrace();
	}

    }
    
    private static void client(String publicKey, String host, String port) throws Exception
    {
	    try
	    {
		Socket socket = new Socket(host, Integer.parseInt(port));
		System.out.println("Connected to: " + host + " on port: " + port);
		ObjectInputStream in = new ObjectInputStream(new FileInputStream(publicKey));
		RSAPublicKey RSApublicKey = (RSAPublicKey) in.readObject();
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128);
		SecretKey sKey = keyGen.generateKey();
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.WRAP_MODE, RSApublicKey);
		byte[] WrappedKey = cipher.wrap(sKey);
		System.out.print("Enter the file path: " );
		Scanner kb = new Scanner(System.in);
		String fPath = kb.next();
		Path path = Paths.get(fPath);
		byte[] data = Files.readAllBytes(path);
		System.out.print("Enter chunk size [1024]: ");
		int chunkSize = kb.nextInt();
		StartMessage sm = new StartMessage(path.getFileName().toString(), WrappedKey, chunkSize);
		System.out.println("Sending: " + fPath + "\tFile Size: " + data.length);
		OutputStream os = socket.getOutputStream();
		ObjectOutputStream oos = new ObjectOutputStream(os);
		oos.writeObject(sm);
		InputStream is = socket.getInputStream();
		ObjectInputStream ois = new ObjectInputStream(is);
		int extra = data.length % chunkSize;
		int chunks = data.length / chunkSize;
		int totalChunks = chunks;
		if(extra > 0)
		{
		    totalChunks++;
		}
		System.out.println("Sending " + totalChunks + " chunks");
		int placement = 0;
		cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.ENCRYPT_MODE, sKey);
		CRC32 crc = new CRC32();
		for(int i = 0; i < chunks; i++)
		{

		    byte[] toSend = new byte[chunkSize];
		    byte[] encrypted = null;
		    for(int j = 0, k = placement; j < chunkSize; j++, k++)
		    {
			toSend[j] = data[k];
		    }
		    AckMessage ackMessage = (AckMessage)ois.readObject();
		    crc.update(toSend);
		    int checkSum = (int)crc.getValue();
		    crc.reset();
		    encrypted = cipher.doFinal(toSend);
		    Chunk chunk = new Chunk(ackMessage.getSeq(), encrypted, checkSum);
		    oos.writeObject(chunk);
		    System.out.println("Chunks completed " + "[" + (i+1) + "/" + totalChunks + "]");
		    placement += chunkSize;
		}
		if(extra > 0)
		{
		    byte[] toSend = new byte[extra];
		    byte[] encrypted = null;
		    for(int j = 0, k = placement; j < extra; j++, k++)
			toSend[j] = data[k];
		    
		    AckMessage ackMessage = (AckMessage)ois.readObject();
		    crc.update(toSend);
		    int checkSum = (int)crc.getValue();
		    crc.reset();
		    encrypted = cipher.doFinal(toSend);
		    Chunk chunk = new Chunk(ackMessage.getSeq(), encrypted, checkSum);
		    System.out.println("Chunks completed " + "[" + totalChunks + "/" + totalChunks + "]");
		    oos.writeObject(chunk);

		}
		in.close();
		oos.close();
		ois.close();
	    }
	    finally {
	    	
	    }

    }



	    private static void server(String privateKey, String port) {
		try {
		    boolean running = true;
		    while(running){

			ServerSocket sSocket = new ServerSocket(Integer.parseInt(port));
			Socket socket = sSocket.accept();
			InputStream is = socket.getInputStream();
			ObjectInputStream ois = new ObjectInputStream(is);
			StartMessage startMessage = (StartMessage)ois.readObject();
			byte[] WrappedKey = startMessage.getEncryptedKey();
			ObjectInputStream in = new ObjectInputStream(new FileInputStream(privateKey));
			RSAPrivateKey rsa = (RSAPrivateKey) in.readObject();
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.UNWRAP_MODE, rsa);
			Key key = cipher.unwrap(WrappedKey, "AES", Cipher.SECRET_KEY);
			System.out.println(startMessage.getFile());
			OutputStream os = socket.getOutputStream();
			ObjectOutputStream oos = new ObjectOutputStream(os);
			int seqNum = 0;
			AckMessage ackMessage = new AckMessage(seqNum);
			seqNum++;
			oos.writeObject(ackMessage);
			cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.DECRYPT_MODE, key);
			String message = "";
			String fileName = startMessage.getFile().replace(".txt", "2.txt");
			PrintWriter pw = new PrintWriter(fileName, "UTF-8");
			byte[] dat = null;
			byte[] decrypted = null;
			Message messages;
			CRC32 crc = new CRC32();
			int chunkNum = (int) startMessage.getSize()/startMessage.getChunkSize();
			if(startMessage.getSize() % startMessage.getChunkSize() >= 1){
			    chunkNum++;
			}
			for(int i = 0; i < chunkNum; i++){
			    messages = (Message)ois.readObject();

			    dat = ((Chunk)messages).getData();
			    decrypted = cipher.doFinal(dat);
			    crc.update(decrypted);
			    int checkSum = (int)crc.getValue();
			    crc.reset();
			    if(checkSum != ((Chunk)messages).getCrc()){
				System.out.println("there was an error when sending the data");
			    }
			    System.out.println("Chunk recieved: [" + seqNum + "/" + chunkNum + "]");
			    message += new String(decrypted);
			    seqNum++;
			    ackMessage = new AckMessage(seqNum);
			    oos.writeObject(ackMessage);
			}
			System.out.println("Transfer complete. Created file: " + fileName);
			pw.print(message);
			pw.close();
			ois.close();
			oos.close();
			in.close();
			is.close();
			os.close();
			sSocket.close();
			socket.close();
		    }
		} catch (Exception e) {
		    System.out.println("error");
		    e.printStackTrace();
		}

	    }

}
