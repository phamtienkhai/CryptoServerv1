package com.kma.cs.utils;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.security.Security;
import java.util.Set;
import java.security.Provider.Service;

import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Main {
//	public static void main(String[] args) throws Exception {
//		System.out.println("Hello World AES-GCM".length());
//		com.kma.cs.main.Main.addProviders();
//		SecretKeyAlgorithmUtils secretKeyAlgorithmUtils = new SecretKeyAlgorithmUtils();
//		SecretKey secretKey = secretKeyAlgorithmUtils.genKey(256, "AES");
//		byte[] iv = CryptoUtils.getRandomNonce(12);
//
////		byte[] dataEncrypt = secretKeyAlgorithmUtils.encryptoData(secretKey, "Hello World AES-GCM, Welcome to Cryptography!".getBytes(StandardCharsets.UTF_8), "AES");
//		byte[] dataEncrypt = EncryptorAesGcm.encryptWithPrefixIV("Hello World AES-GCM, Welcome to Cryptography!".getBytes(StandardCharsets.UTF_8), secretKey, iv);
//		//		System.out.println(dataEncrypt);
////		System.out.println("helloworldccfdsc".getBytes().length);
//		byte[] dataDecyrpt = secretKeyAlgorithmUtils.dycryptoData(secretKey, dataEncrypt, "AES");
////		System.out.println("dataDecyrpt.length:"+dataDecyrpt.length);
//		System.out.println("giai ma:"+new String(dataDecyrpt));
////		System.out.println("aaa");
////		System.out.println("howtodoinjava.com".length());
////		secretKeyAlgorithmUtils.encryptFile(secretKey, "AES");
////		secretKeyAlgorithmUtils.decryptFile(secretKey, "AES");
//	}
	
	public static void main(String[] args) {
		Main.addProviders();
		Main.getProvider();
//		System.out.println(PublicKeyAlgorithmUtils.genRandomString(12));
	}
	
	public static void getProvider() {
//		Provider[] providers = Security.getProviders();
		Provider provider = Security.getProvider("BC");
//		Set<Service> services = provi
//		for(Provider provider : providers) {
			Set<Service> services = provider.getServices();
			System.out.println("Provider Name:"+provider.getName());
			for(Service service : services) {
//				System.out.println(service.getAlgorithm());
//				service.get
//				if(service.getClassName().contains("Cipher")) {
				if(service.getAlgorithm().contains("ElGamal")) {
					System.out.println(service.getAlgorithm()+"-"+service.getClassName());
				}
			}
			System.out.println("\n\n\n");
//		}
	}
	
	public static void addProviders() {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	public static String convertBytesToBase64(byte[] dataByteToBase64) {
		return java.util.Base64.getEncoder().encodeToString(dataByteToBase64);
	}
	
	public static byte[] convertBase64ToBytes(byte[] dataByteToBase64) {
		return java.util.Base64.getDecoder().decode(dataByteToBase64);
	}
	
	public static void writeFile(String path, String data) {
		try {
			FileOutputStream fos = new FileOutputStream(path);
			fos.write(data.getBytes());
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return;
	}
	
	public static byte[] readFile(String path) {
		try {
			FileInputStream fis = new FileInputStream(path);
			byte[] data = new byte[fis.available()];
			fis.read(data);
			return data;
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
}
