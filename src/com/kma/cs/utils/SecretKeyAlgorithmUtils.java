package com.kma.cs.utils;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class SecretKeyAlgorithmUtils {

//	private static final String ENCRYPT_ALGO = "AES/GCM/NoPadding";
	private static final int TAG_LENGTH_BIT = 128;
	private static final int IV_LENGTH_BYTE = 12;
	private static final int AES_KEY_BIT = 256;

	private static final Charset UTF_8 = StandardCharsets.UTF_8;

	private static final String providerBC = "BC";
	
	private static Cipher cipher;
	
	static {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	public static SecretKey genKey(int size, String algorithm) {
		Security.addProvider(new BouncyCastleProvider());
		try {
			KeyGenerator kg = KeyGenerator.getInstance(algorithm, providerBC);
			kg.init(size, SecureRandom.getInstanceStrong());
			SecretKey secretKey = kg.generateKey();
			return secretKey;
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			System.out.println("Khong tim thay thuat toan");
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			System.out.println("Khong tim thay provider");
			e.printStackTrace();
		}
		return null;
	}
	
	public static byte[] encryptData(SecretKey secretKey, byte[] data, String algorithm) {
		try {
			cipher = Cipher.getInstance(algorithm, providerBC);
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);
			byte[] dataEncyrpted = cipher.doFinal(data);
			return dataEncyrpted;
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	public static byte[] decryptData(SecretKey secretKey, byte[] data, String algorithm) {
		try {
			cipher = Cipher.getInstance(algorithm, providerBC);
			cipher.init(Cipher.DECRYPT_MODE, secretKey);
			byte[] dataEncyrpted = cipher.doFinal(data);
			return dataEncyrpted;
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());
		String data = "Hom nay la 1 ngay binh thuong va cung rat la binh thuong";
		SecretKey secret = genKey(192, "DESEDE");
		byte[] cipherByte = encryptData(secret, data.getBytes(), "DESEDE");
		byte[] planietext = decryptData(secret, cipherByte, "DESEDE");
		System.out.println(new String(planietext));
	}

//	public SecretKey genKey(int size, String algorithm) {
//		try {
//			KeyGenerator kg = KeyGenerator.getInstance("AES", providerBC);
//			kg.init(size, SecureRandom.getInstanceStrong());
//			SecretKey secretKey = kg.generateKey();
//			return secretKey;
//		} catch (NoSuchAlgorithmException e) {
//			// TODO Auto-generated catch block
//			System.out.println("Khong tim thay thuat toan");
//			e.printStackTrace();
//		} catch (NoSuchProviderException e) {
//			// TODO Auto-generated catch block
//			System.out.println("Khong tim thay provider");
//			e.printStackTrace();
//		}
//		return null;
//	}
//
//	public byte[] getRandomNonce(int numBytes) {
//		byte[] nonce = new byte[numBytes];
//		new SecureRandom().nextBytes(nonce);
//		return nonce;
//	}
//
//	public byte[] encryptoData(SecretKey secretKey, byte[] dataToEncrypt, String algorithm) {
//		try {
//			byte[] iv = getRandomNonce(IV_LENGTH_BYTE);
//			Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO, providerBC);
//			cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
////			cipher.init(Cipher, secretKey, null);
//			cipher.update(dataToEncrypt);
//			byte[] cipherText = cipher.doFinal();
////			System.out.println("dataEncrypt.length:" + dataEncrypt.length);
////			System.out.println(cipher.get);
//			byte[] cipherTextWithIv = ByteBuffer.allocate(iv.length + cipherText.length).put(iv).put(cipherText)
//					.array();
//			return cipherTextWithIv;
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
//		} catch (InvalidAlgorithmParameterException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//		return null;
//	}
//
//	public byte[] dycryptoData(SecretKey secretKey, byte[] dataToDycrypt, String algorithm) {
//		try {
//			ByteBuffer bb = ByteBuffer.wrap(dataToDycrypt);
//			byte[] iv = new byte[IV_LENGTH_BYTE];
//			bb.get(iv);
////			bb.get(iv, 0, iv.length);
////			System.out.println("bb.remaining():"+bb.remaining());
//			byte[] cipherText = new byte[bb.remaining()];
//			bb.get(cipherText);
////			byte[] i = getRandomNonce(12);
//			Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO, providerBC);
//			cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
////			System.out.println("cipherText.length:"+cipherText.length);
//			cipher.update(cipherText);
//			byte[] dataDycrypt = cipher.doFinal();
//			return dataDycrypt;
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
//		} catch (InvalidAlgorithmParameterException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//		return null;
//	}
//
//	public static void encryptFile(SecretKey secretKey, String algorithm) {
//		try {
//			Cipher cipher = Cipher.getInstance(algorithm, providerBC);
//			cipher.init(Cipher.ENCRYPT_MODE, secretKey);
//			ObjectOutputStream fos = new ObjectOutputStream(
//					new FileOutputStream("D:\\CryptographyServices\\Code\\files\\keyspec\\b.txt"));
//			FileInputStream fis = new FileInputStream("D:\\CryptographyServices\\Code\\files\\keyspec\\a.txt");
////			CipherOutputStream cos = new CipherOutputStream(fos, cipher);
//			CipherInputStream cis = new CipherInputStream(fis, cipher);
////			System.out.println(cis.available());
////			byte[] data = new byte[] 
////			cis.read(null)
////			return null;
//
//		} catch (FileNotFoundException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
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
//		} catch (IOException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//
//	}
//
//	public static void decryptFile(SecretKey secretKey, String algorithm) {
//		try {
//			Cipher cipher = Cipher.getInstance(algorithm, providerBC);
//			cipher.init(Cipher.DECRYPT_MODE, secretKey);
//			FileOutputStream fos = new FileOutputStream("D:\\CryptographyServices\\Code\\files\\keyspec\\c.txt");
//			FileInputStream fis = new FileInputStream("D:\\CryptographyServices\\Code\\files\\keyspec\\b.txt");
//			CipherInputStream cis = new CipherInputStream(fis, cipher);
//			BufferedReader br = new BufferedReader(new InputStreamReader(cis));
//			System.out.println(br.readLine());
//
//		} catch (FileNotFoundException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
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
//		} catch (IOException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//
//	}
}
