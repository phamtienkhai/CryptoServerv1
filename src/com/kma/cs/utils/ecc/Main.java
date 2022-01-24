package com.kma.cs.utils.ecc;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

public class Main {
	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		KeyPairGenerator ecKeyGen = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
		ecKeyGen.initialize(new ECGenParameterSpec("secp256r1"));

		KeyPair ecKeyPair = ecKeyGen.generateKeyPair();
		System.out.println("What is slow?");

		Cipher iesCipher = Cipher.getInstance("ECIESwithAES-CBC");
		Cipher iesDecipher = Cipher.getInstance("ECIESwithAES-CBC");
		iesCipher.init(Cipher.ENCRYPT_MODE, ecKeyPair.getPublic());

		String message = "Hello World";

		byte[] ciphertext = iesCipher.doFinal(message.getBytes());
		System.out.println(Hex.toHexString(ciphertext));

		iesDecipher.init(Cipher.DECRYPT_MODE, ecKeyPair.getPrivate(), iesCipher.getParameters());
		byte[] plaintext = iesDecipher.doFinal(ciphertext);

		System.out.println(new String(plaintext));
	}
}
