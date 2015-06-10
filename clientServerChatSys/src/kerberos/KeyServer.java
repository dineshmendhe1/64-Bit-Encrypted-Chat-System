package kerberos;

import cipher.*;

import java.io.*;
import java.net.*;
import java.util.*;
import java.math.*;

/**
 * keyServer configuration.
 * @author Dinesh Mendhe
 */

public class KeyServer {

	public DES blockCipher;
	public byte[] KAB; // KAB is a session key.
	public int SERVER_PORT;
	public Map<Integer, byte[]> pkPairMap;

	public KeyServer() {
		
		
		pkPairMap = new HashMap<Integer, byte[]>();
		this.KAB= new byte[8];
	}

	
	public long byteToLong(byte[] byteArray) {
		long longValue = 0l;
		for (int i = 0; i < 8; i++)
			longValue = (longValue << 8) | (byteArray[i] & 0xffl);
		return longValue;
	}

	public byte[] longToByte(long longValue) {
		byte[] byteArray = new byte[8];
		for (int i = 7; i >= 0; i--) {
			byteArray[i] = (byte) (longValue & 0xffl);
			longValue = longValue >> 8;
		}
		return byteArray;
	}
	// Generate random session key(KAB).
	byte kab1[] = new byte[8];
	public byte[] randomKAB() {
		Random rand;
		int seedNo = 255; 
		int sValue = 0;
		rand = new Random();
		while (sValue < 8) {
			kab1[sValue] = (byte)(rand.nextInt(seedNo));
			sValue++;
		}
		return kab1;
	}
	public static void main(String[] args) throws IOException {

		System.out.printf("%s", "keyServer Started.");
		System.out.println(" ");
		DES blockCipher = new DES("sboxes_default");
		int SERVER_PORT = Integer.parseInt(args[0]);
		KeyServer ks_obj = new KeyServer();
		ks_obj.SERVER_PORT = SERVER_PORT;
		ServerSocket serverSock =  null;
		BufferedInputStream inputStream = null;
		OutputStream outputStream = null;
		Socket client = null;
		int len = args.length, counter = 1;
		byte content[] = new byte[4];
		
		while (counter < len){
			int USER_PORT = Integer.parseInt(args[counter++]);
			Long longKey = new BigInteger(args[counter], 16).longValue();
			byte[] USER_KEY = ks_obj.longToByte(longKey);
			// storing userport and userkey in hashmap.
			ks_obj.pkPairMap.put(USER_PORT, USER_KEY);
			counter++;
		}
		// view the content inside hashmap.
		//System.out.println("HashMap port and key values: " + ks_obj.pkPairMap);
		
		try {
			//socket will be used to read and write over communication channel.
			serverSock = new ServerSocket(ks_obj.SERVER_PORT);
			
			for ( ; ; ) {
				client = serverSock.accept();
				outputStream = client.getOutputStream();
				inputStream = new BufferedInputStream(client.getInputStream());
				inputStream.read(content);
				String in = new String(content);
				int client_port = ((content[1] & 0xff)<<8) | (content[0] & 0xff);  
				int userver_port = ((content[1] & 0xff)<<8) | (content[2] & 0xff);
				//blockCipher.encrypt(KA,DES(..).)
				//outputStream.write(..)
				/*the key server returns:
					bytes [0-7] : DES (KA, KAB)
					bytes[8-15] : DES(KA, DES(KB, KAB))*/
				//using port number to get respective key value from hashmap.
				byte[] KB = ks_obj.pkPairMap.get(userver_port);
				byte[] KAB = ks_obj.randomKAB();
				byte[] KAS = blockCipher.encrypt(ks_obj.pkPairMap.get(client_port), KAB);
				byte[] BKeyEnc= blockCipher.encrypt(ks_obj.pkPairMap.get(userver_port), KAB);
				byte[] KBS = blockCipher.encrypt(ks_obj.pkPairMap.get(client_port), BKeyEnc );
				outputStream.write(KAS);
				outputStream.write(KBS);
				outputStream.flush();
				System.out.println("Connected.");
			}
		}
		 
		catch (IOException e) {
			
			System.out.printf("%s", "IOException occured.");
			System.exit(1);
			
		} finally{
			
			try {
				if (outputStream != null)
					outputStream.close();

				if (inputStream != null)
					inputStream.close();
				if (serverSock != null)
					serverSock.close();
		} catch(IOException e){
			
			System.out.printf("%s", "IOException occured.");
		}
			
		}

			
	}

}
