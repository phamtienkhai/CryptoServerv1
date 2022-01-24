package com.kma.cs.utils;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.List;

public class CryptoUtils {

	public static byte[] getRandomNonce(int numBytes) {
		byte[] nonce = new byte[numBytes];
		new SecureRandom().nextBytes(nonce);
		return nonce;
	}

	// AES secret key
	public static SecretKey getAESKey(int keysize) throws NoSuchAlgorithmException {
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(keysize, SecureRandom.getInstanceStrong());
		return keyGen.generateKey();
	}

	// Password derived AES 256 bits secret key
	public static SecretKey getAESKeyFromPassword(char[] password, byte[] salt)
			throws NoSuchAlgorithmException, InvalidKeySpecException {

		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		// iterationCount = 65536
		// keyLength = 256
		KeySpec spec = new PBEKeySpec(password, salt, 65536, 256);
		SecretKey secret = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
		return secret;

	}

	// hex representation
	public static String hex(byte[] bytes) {
		StringBuilder result = new StringBuilder();
		for (byte b : bytes) {
			result.append(String.format("%02x", b));
		}
		return result.toString();
	}

	// print hex with block size split
	public static String hexWithBlockSize(byte[] bytes, int blockSize) {

		String hex = hex(bytes);

		// one hex = 2 chars
		blockSize = blockSize * 2;

		// better idea how to print this?
		List<String> result = new ArrayList<>();
		int index = 0;
		while (index < hex.length()) {
			result.add(hex.substring(index, Math.min(index + blockSize, hex.length())));
			index += blockSize;
		}

		return result.toString();

	}

//	public static void main(String[] args) {
//		
//	}

	public static KeyStore createCryptoToken(String path, String password) {
		KeyStore ks;
		try {
			ks = KeyStore.getInstance("PKCS12");
			ks.load(null, null);
			ks.store(new FileOutputStream(path), password.toCharArray());
			return ks;
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	public static void setEntry(String path, String password, String secretKeyAlias) {
		KeyStore ks;
		try {
			ks = KeyStore.getInstance("PKCS12");
			ks.load(new FileInputStream(path), password.toCharArray());
			KeyStore.ProtectionParameter protectionParam = new KeyStore.PasswordProtection(password.toCharArray());
			SecretKey mySecretKey = new SecretKeySpec("myPassword".getBytes(), "AES");
			KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(mySecretKey);
			ks.setEntry(secretKeyAlias, secretKeyEntry, protectionParam);
			ks.store(new FileOutputStream(path), password.toCharArray());
//			ks.store(new FileOutputStream(path), password.toCharArray());
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public static void setKeyEntry(String path, String password, Key key, java.security.cert.Certificate[] certChain, String aliase) {
		KeyStore ks;
		try {
			ks = KeyStore.getInstance("PKCS12");
			ks.load(new FileInputStream(path), password.toCharArray());
			ks.setKeyEntry(aliase, key, password.toCharArray(), certChain);
			ks.store(new FileOutputStream(path), password.toCharArray());
//			ks.store(new FileOutputStream(path), password.toCharArray());
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public static void main(String[] args) {
		KeyStore ks = createCryptoToken("D:\\token.jks", "1");
		setEntry("D:\\token.jks", "1", "1");
		PublicKeyAlgorithmUtils.genKey("RSA", 2048);
		try {
			byte[] csr = PublicKeyAlgorithmUtils.generatePKCS10("KhaiPT", "", "", "", "", "VN");
//			byte[] csr = generatePKCS10("KhaiPT", "", "", "", "", "VN");
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		setKeyEntry(null, null, null, null, null);
//		Entry entry = 
	}

}
