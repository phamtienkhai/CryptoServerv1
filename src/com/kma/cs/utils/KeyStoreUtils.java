package com.kma.cs.utils;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class KeyStoreUtils {
	private String path;
	private char[] password;
	private KeyStore keyStore;
	private String type;
	private String aliase;
	
	public KeyStoreUtils(String path, char[] password, String type) {
		this.path = path;
		this.password = password;
		this.type = type;
		init();
		getAliase();
	}
	
	public void init() {
		try {
			keyStore = KeyStore.getInstance(type);
			keyStore.load(new FileInputStream(path), password);
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public KeyStore getKeyStore() {
		return keyStore;
	}
	
	public PrivateKey getPrivateKey(String aliase, char[] password) {
		PrivateKey privateKey = null;
		try {
			privateKey = (PrivateKey) keyStore.getKey(aliase, password);
			if(privateKey == null)
				privateKey = (PrivateKey) keyStore.getKey(this.aliase, password);
			return privateKey;
		} catch (UnrecoverableKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	public Certificate getCert(String aliase) {
		Certificate cert = null;
		try {
			cert = keyStore.getCertificate(aliase);
			if(cert == null)
				cert = keyStore.getCertificate(this.aliase);
			return cert;
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	public Certificate[] getCertChain(String aliase) {
		Certificate[] certChain = null;
		try {
			certChain = keyStore.getCertificateChain(aliase);
			if(certChain == null)
				certChain = keyStore.getCertificateChain(this.aliase);
			return certChain;
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	public String getAliase() {
		try {
			Enumeration<String> aliases = keyStore.aliases();
			while(aliases.hasMoreElements()) {
				String aliase = aliases.nextElement();
				if(keyStore.isKeyEntry(aliase))
					this.aliase = aliase;
			}
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	public CryptoToken getCryptoToken() {
		return new CryptoToken(getPrivateKey(aliase, password), getCert(aliase), getCertChain(aliase));
	}
	
	public static boolean setKeyStoreSecretKey(String path, String password, SecretKey secretKey, String aliase) {
		try {
			KeyStore keyStore = KeyStore.getInstance("PKCS12");
			try {
				keyStore.load(new FileInputStream(path), password.toCharArray());
			} catch (Exception e) {
				keyStore.load(null, null);
			}
//			keyStore.load(new FileInputStream(path), password.toCharArray());
			KeyStore.ProtectionParameter protectionParam = new KeyStore.PasswordProtection(password.toCharArray());
			KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(secretKey);
			keyStore.setEntry(aliase, secretKeyEntry, protectionParam);
			keyStore.store(new FileOutputStream(path), password.toCharArray());
			return true;
//			keyStore.setKey
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
		return false;
	}
	
	public static boolean setKeyStorePKI(String path , String password, PrivateKey privateKey, Certificate[] certChain, String aliase) {
		try {
			KeyStore keyStore = KeyStore.getInstance("PKCS12");
			try {
				keyStore.load(new FileInputStream(path), password.toCharArray());
			} catch (Exception e) {
				keyStore.load(null, null);
			}
			keyStore.setKeyEntry(aliase, privateKey, password.toCharArray(), certChain);
			FileOutputStream os = new FileOutputStream(path);
			keyStore.store(os, password.toCharArray());
			os.close();
			return true;
//			keyStore.setKey
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
		return false;
	}
	
//	public static SecretKey getSecretKey(String path, String pass, String algorithmName) {
	public static SecretKey getSecretKey(String path, String pass, String userName) {
		try {
			KeyStore keyStore = KeyStore.getInstance("PKCS12");
			try {
				keyStore.load(new FileInputStream(path), pass.toCharArray());
			} catch (Exception e) {
				keyStore.load(null, null);
			}
			Enumeration<String> aliases =  keyStore.aliases();
			String aliase = null;
			while(aliases.hasMoreElements()) {
				aliase = aliases.nextElement();
				Key key = keyStore.getKey(aliase, pass.toCharArray());
				if(userName.equalsIgnoreCase(aliase)) {
					return (SecretKey) key;
				} 
			}
			return null;
//			keyStore.setKey
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
		} catch (UnrecoverableKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	public static CryptoToken getCryptoToken(String path, String pass, String aliase) {
		try {
//			CryptoToken cryptoToken = new CryptoToken(null, null, null)
			KeyStore keyStore = KeyStore.getInstance("PKCS12");
			try {
				keyStore.load(new FileInputStream(path), pass.toCharArray());
			} catch (Exception e) {
				keyStore.load(null, null);
			}
			Enumeration<String> aliases =  keyStore.aliases();
			String aliase2 = null;
			while(aliases.hasMoreElements()) {
				aliase2 = aliases.nextElement();
				System.out.println("aliase2:"+aliase2);
				if(aliase2.equals(aliase)) {
					Key key = keyStore.getKey(aliase, pass.toCharArray());
					CryptoToken cryptoToken = new CryptoToken((PrivateKey) key, keyStore.getCertificate(aliase), keyStore.getCertificateChain(aliase));
//					return (SecretKey) key;
					return cryptoToken;
				} 
			}
			return null;
//			keyStore.setKey
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
		} catch (UnrecoverableKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	public static boolean checkKey(String path, String password, String aliase) {
		try {
			KeyStore ks = KeyStore.getInstance("PKCS12");
			ks.load(new FileInputStream(path), password.toCharArray());
			Enumeration<String> aliases =  ks.aliases();
			while(aliases.hasMoreElements()) {
				String aliase2 = aliases.nextElement();
				if(aliase2.equalsIgnoreCase(aliase))
					return true;
			}
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
	}
	
	public static List loadKey(String pathKeyStore, String password) {
		List listAliases = new ArrayList();
		try {
			KeyStore keyStore = KeyStore.getInstance("PKCS12");
			keyStore.load(new FileInputStream(pathKeyStore), password.toCharArray());
			Enumeration<String> aliases = keyStore.aliases();
			String aliase = "";
			while(aliases.hasMoreElements()) {
				aliase = aliases.nextElement();
				listAliases.add(aliase);
			}
//			keyStore.
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return listAliases;
	}
	
	public static String getKeyAlg(String aliase, String pathKeyStore, String password) {
		String alg = "";
		try {
			System.out.println("pathKeyStore:"+pathKeyStore);
			System.out.println("password:"+password);
			pathKeyStore = pathKeyStore.replaceAll("\\\\", "/");
			KeyStore keyStore = KeyStore.getInstance("PKCS12");
			keyStore.load(new FileInputStream(pathKeyStore), password.toCharArray());
			Key key = keyStore.getKey(aliase, password.toCharArray());
			alg = key.getAlgorithm();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnrecoverableKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return alg;
	}
	
	public static void main(String[] args) {
		//String path , String password, SecretKey secretKey, String aliase
		SecretKey mySecretKey = new SecretKeySpec("myPassword".getBytes(), "DSA");
		setKeyStoreSecretKey("D:\\CryptographyServices\\file test\\secretkey\\docs\\aaa.p12", "1", mySecretKey, "1");
	}
}
