package kerberos;

import cipher.*;
import java.io.*;
import java.net.*;
import java.math.*;

/**
 * userClient configuration.
 * @author Dinesh Mendhe
 */

 /*userClient cml arguments KS_HOST, KS_PORT, OTHER_HOS, OTHER_PORT, USER_PORT,
 USER_KEY*/

public class UserClient {

	public int KS_PORT, OTHER_PORT, USER_PORT;
	public byte[] USER_KEY;
	public String KS_HOST, OTHER_HOST;
	public byte[] KAB;

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

	public static void main(String[] args) throws IOException {
		
		System.out.println("User Client Started.");
		UserClient uc_obj = new UserClient();
		uc_obj.KS_HOST = args[0];
		uc_obj.KS_PORT = Integer.parseInt(args[1]);
		uc_obj.OTHER_HOST = args[2];
		uc_obj.OTHER_PORT = Integer.parseInt(args[3]);
		uc_obj.USER_PORT = Integer.parseInt(args[4]);
		Long key = new BigInteger(args[5], 16).longValue();
		uc_obj.USER_KEY = uc_obj.longToByte(key);
		DES blockCipher = new DES("sboxes_default");
		CBC cipherMode  = new CBC(blockCipher);
		Socket serverSock = null;
		BufferedOutputStream outputStream = null;
		BufferedInputStream inputStream = null;
		BufferedOutputStream us_outputStream = null;
		BufferedReader in;
		InputStream us_inputStream = null;
		Socket userSerSock = null;
	    String cont;
		byte[] pByte = new byte[4];
		in = new BufferedReader(new InputStreamReader(System.in));
		byte []messageEnc1;
		String userInput;
		
		try {
			// session key for A and B i.e. session key of user client and user server.
			byte[] KAS = new byte[8];
			byte[] KBS = new byte[8];
			// creating socket for communication and read-write operation over the comm. channel.
			// userserSock  with other server/ userServer details.
			// serversock with key server details.
			userSerSock = new Socket(uc_obj.OTHER_HOST, uc_obj.OTHER_PORT);
			serverSock = new Socket(uc_obj.KS_HOST, uc_obj.KS_PORT);
			outputStream = new BufferedOutputStream(serverSock.getOutputStream());
			inputStream = new BufferedInputStream(serverSock.getInputStream());
			us_outputStream = new BufferedOutputStream( userSerSock.getOutputStream());	
			us_inputStream = userSerSock.getInputStream();
			pByte[0] = (byte) (uc_obj.USER_PORT & 0xff);
			pByte[1] = (byte) ( (uc_obj.USER_PORT >> 8 ) & 0xff);
			pByte[2] = (byte) (uc_obj.OTHER_PORT & 0xff);
			pByte[3] = (byte) ( (uc_obj.OTHER_PORT>> 8 ) & 0xff);
			//writing to output stream.
			outputStream.write(pByte);
			// flushing  the output stream.
			outputStream.flush();
			// reading from input stream
			inputStream.read(KAS);
			inputStream.read(KBS);
			//session key KAB.
			byte[] KBS_enc = blockCipher.decrypt(uc_obj.USER_KEY,KBS );
			uc_obj.KAB = blockCipher.decrypt(uc_obj.USER_KEY, KAS);
			
			System.out.println("Enter text -");
			String input = in.readLine();
			byte[] message = input.getBytes();
			byte[] IV = new byte[8];
			int len2 = message.length;
			int IV1= len2 + 8 - (len2 % 8);
			IV[0] = (byte) (IV1 & 0xff);
			IV[1] = (byte) ((IV1 >> 8) & 0xff);
			IV[2]=IV[3] = IV[4] = IV[5]= IV[6]= IV[7]= 0x00;
			//setting IV in CBC cipher mode.
			cipherMode.setIV(IV);
			
			// encrypting(using CBC) and sending message over communication channel.
			byte[]  messageEnc = cipherMode.encrypt(uc_obj.KAB, message);
			// writing encrypted message to user server output stream.
			us_outputStream.write(KBS_enc);
			us_outputStream.write(messageEnc);			
			us_outputStream.flush();
			
			for ( ; ; ){
				messageEnc1 = new byte[100];
				us_inputStream.read(messageEnc1);
				// decrypting response from user server using CBC decrypt.
				byte[] usrServerResp = cipherMode.decrypt(uc_obj.KAB, messageEnc1);
				System.out.printf("Response from the another host/ userServer - %s",new String(usrServerResp));
				System.out.println();
				System.out.println("Enter the text to send - ");
				// making IV to number of bites the plaintext.
				userInput = in.readLine();
				int userInlen = userInput.length();
				IV1 = userInlen + 8 - (userInlen % 8);
				IV = new byte[8];
				IV[0] = (byte) (IV1 & 0xff);
				IV[1] = (byte) ((IV1 >> 8) & 0xff);
				IV[2] = IV[3] = IV[4] = IV[5] = IV[6] = IV[7] = 0x00;
				cipherMode.setIV(IV);
				us_outputStream.write(cipherMode.encrypt(uc_obj.KAB, userInput.getBytes()));
				// flushing the output stream.
				us_outputStream.flush();					
			}
			
		} catch (UnknownHostException e) {

			System.out.printf("%s", "Exception Occurred : Unknown host.");
			System.exit(1);

		} catch (IOException e) {

			System.out.printf("%s", "IOException occured");
			System.exit(1);
		}

		finally {
			
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
		System.out.printf("%s", "UserClient started.");
	}
}
