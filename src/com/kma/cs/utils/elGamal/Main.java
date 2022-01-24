package com.kma.cs.utils.elGamal;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

public class Main {
	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		Security.addProvider(new BouncyCastlePQCProvider());

		byte[] input = "ab".getBytes();
		Cipher cipher = Cipher.getInstance("ElGamal/None/NoPadding");
		KeyPairGenerator generator = KeyPairGenerator.getInstance("ElGamal");
		SecureRandom random = new SecureRandom();

//		generator.initialize(128, random);
//		generator.initialize(128);
//		generator.initialize(null)

		KeyPair pair = generator.generateKeyPair();
		Key pubKey = pair.getPublic();
		Key privKey = pair.getPrivate();
		cipher.init(Cipher.ENCRYPT_MODE, pubKey, random);
		byte[] cipherText = cipher.doFinal(input);
		System.out.println("cipher: " + new String(cipherText));

		cipher.init(Cipher.DECRYPT_MODE, privKey);
		byte[] plainText = cipher.doFinal(cipherText);
		System.out.println("plain : " + new String(plainText));
	}
}
