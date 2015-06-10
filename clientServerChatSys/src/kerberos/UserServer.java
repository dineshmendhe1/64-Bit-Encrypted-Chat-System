package kerberos;

import cipher.*;

import java.math.*;
import java.io.*;
import java.net.*;

/**
 * userServer configuration.
 * @author Dinesh Mendhe
 */

public class UserServer {

	byte[] USER_KEY;
	int USER_PORT;
	byte[] KAB;
	
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

 /* user server receive the ticket having
  * bytes[0-7] : DES(KB, KAB)
  * bytes[8-] : CBC (KAB, "msg")
  * It will decrypt using his own key to get session key and start communication.
  * */
	
	public static void main(String[] args) throws IOException {
		
		UserServer us_obj;
		Long longKey;
		us_obj = new UserServer();
		DES blockCipher = new DES("sboxes_default");
		CBC cipherMode = new CBC(blockCipher);
		longKey = new BigInteger(args[1], 16).longValue();
		us_obj.USER_KEY = us_obj.longToByte(longKey);
		us_obj.USER_PORT = Integer.parseInt(args[0]);
		ServerSocket serverSock =  null;
		Socket clientSock = null;
		InputStream inputStream = null;
		OutputStream outputStream = null;
		BufferedReader input = null;
		String userInput;
		byte[] textEnc;
		byte[] textIn;
		byte[] textCont;
		byte[] IV = new byte[8];
		System.out.printf("%s", "UserServer Started.");
		System.out.println(" ");
		
		/*userServer first receive a socket connection, with following msg.
		bytes[0-7] : DES(KB,KAB)
		bytes[8-] : CBC(KAB, "here is the content...")*/
		
		try{
			serverSock = new ServerSocket(us_obj.USER_PORT);
			clientSock = serverSock.accept();
			System.out.printf("%s","Connected to Client. ");
			inputStream = clientSock.getInputStream();
			
			byte[] KAB_encrypted = new byte[8];
			byte[] encry_data = new byte [100];
			inputStream.read(KAB_encrypted);
			inputStream.read(encry_data);
			us_obj.KAB = blockCipher.decrypt(us_obj.USER_KEY, KAB_encrypted);
			textCont = cipherMode.decrypt(us_obj.KAB, encry_data);
			//reading from standard input.
			input = new BufferedReader(new InputStreamReader(System.in));
			outputStream = clientSock.getOutputStream();
			System.out.println();
			System.out.println("Enter text to forward to client.- ");
			
			while (true){
				userInput = input.readLine();
				int len1 = userInput.length();
				// making IV to number of bites the plaintext.
				int IV1= len1 + 8 - (len1 % 8);				
				IV[0]=(byte) (IV1 & 0xff);
				IV[1]=(byte) ((IV1 >> 8) & 0xff);
				IV[2]=IV[3] = IV[4] = IV[5]= IV[6]= IV[7]= 0x00;
				
				cipherMode.setIV(IV);
				textEnc = cipherMode.encrypt(us_obj.KAB,userInput.getBytes());
				outputStream.write(textEnc);
				outputStream.flush();
				textIn = new byte[100];
				inputStream.read(textIn);
				byte decText[] = cipherMode.decrypt(us_obj.KAB,textIn);
				System.out.println(" ");
				System.out.printf("Response from user client - %s", new String(decText));
				System.out.println();
				System.out.println("Enter text to send - ");

			}
		} catch (IOException e){
			
			//System.out.printf("%s", "IOException occured");
			//System.exit(1);
			
		}finally {
			
			try {
				if (outputStream != null)
					outputStream.close();

				if (inputStream != null)
					inputStream.close();
				
				if (serverSock != null)
					serverSock.close();

			} catch (IOException e) {
				
				System.out.printf("%s", "IOException Occured.");
			}
		}
		
	}
}
