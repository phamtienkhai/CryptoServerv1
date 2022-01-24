package com.kma.cs.utils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class HashUtil {
	private static MessageDigest md;
	
	public static String hash(String data) {
		try {
			Security.addProvider(new BouncyCastleProvider());
			md = MessageDigest.getInstance("SHA256");
			md.update(data.getBytes());
			byte[] hashCode = md.digest();
			return java.util.Base64.getEncoder().encodeToString(hashCode);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
}
