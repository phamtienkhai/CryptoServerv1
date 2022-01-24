package com.kma.cs.utils;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class SecretKeyAlgorithmUtils2 {

	private static final int TAG_LENGTH_BIT = 128;
	private static final int IV_LENGTH_BYTE = 12;
	private static final int AES_KEY_BIT = 256;
	private static final Charset UTF_8 = StandardCharsets.UTF_8;

	public static String encryptDataAES(String pText, SecretKey secretKey) {
		String OUTPUT_FORMAT = "%-30s:%s";

//		String pText = "Hello World AES-GCM, Welcome to Cryptography!";
		byte[] iv = CryptoUtils.getRandomNonce(IV_LENGTH_BYTE);
		byte[] encryptedText = null;
		try {
			encryptedText = EncryptorAesGcm.encryptWithPrefixIV(pText.getBytes(UTF_8), secretKey, iv);
			return Main.convertBytesToBase64(encryptedText);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	public static String decryptDataAES(String cipherText, SecretKey secretKey) {
		byte[] dataEncrypt = Main.convertBase64ToBytes(cipherText.getBytes());
		String decryptedText = null;
		try {
			decryptedText = EncryptorAesGcm.decryptWithPrefixIV(dataEncrypt, secretKey);
			return decryptedText;
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	public static void main(String[] args) {
		//thuat toan AES
		String pathPlainText = "D:\\CryptographyServices\\file test\\secretkey\\docs\\plaintext.txt";
		String pathCipherText = "D:\\CryptographyServices\\file test\\secretkey\\docs\\ciphertext.txt";
		String outputText = "D:\\CryptographyServices\\file test\\secretkey\\docs\\output.txt";
		try {
			SecretKey secretKey = CryptoUtils.getAESKey(AES_KEY_BIT);
//			String dataToEncrypt = "Hello World AES-GCM, Welcome to Cryptography!";
			String dataToEncrypt = new String(Main.readFile(pathPlainText));
			String dataEncrypt = SecretKeyAlgorithmUtils2.encryptDataAES(dataToEncrypt, secretKey);
			System.out.println("Cipher Text:" + dataEncrypt);
			Main.writeFile(pathCipherText, dataEncrypt);
			String dataCipher = new String(Main.readFile(pathCipherText));
//			System.out.println(dataCipher);
			String plainText = SecretKeyAlgorithmUtils2.decryptDataAES(dataCipher, secretKey);
			System.out.println("Plain Text:" + plainText);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		//thuat toan DES
//		Main.addProviders();
//		SecretKey secretKey = genSecretKey(64);
//		String dataEncrypt = SecretKeyAlgorithmUtils2.encryptDataDES(dataToEncrypt, secretKey);
//		System.out.println("dataEncrypt:"+dataEncrypt);
	}
	
//	public static SecretKey genSecretKey(int size) {
//		try {
//			KeyGenerator kg = KeyGenerator.getInstance("DES", "BC");
//			kg.init(size);
//			SecretKey secretKey = kg.generateKey();
//			return secretKey;
//		} catch (NoSuchAlgorithmException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		} catch (NoSuchProviderException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//		return null;
//	}
//	
//	public static String encryptDataDES(String pText, SecretKey secretKey) {
//		try {
//			Cipher cipher = Cipher.getInstance("DES", "BC");
//			cipher.init(Cipher.ENCRYPT_MODE, secretKey);
//			cipher.update(pText.getBytes());
//			byte[] dataEncrypt = cipher.doFinal();
//			return Main.convertBytesToBase64(dataEncrypt);
//		} catch (NoSuchAlgorithmException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		} catch (NoSuchProviderException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		} catch (NoSuchPaddingException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		} catch (InvalidKeyException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		} catch (IllegalBlockSizeException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		} catch (BadPaddingException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//		return null;
//	}
}
