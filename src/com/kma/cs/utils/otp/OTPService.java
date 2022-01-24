package com.kma.cs.utils.otp;

import com.bastiaanjansen.otp.HMACAlgorithm;
import com.bastiaanjansen.otp.SecretGenerator;
import com.bastiaanjansen.otp.TOTPGenerator;

public class OTPService {
	
	static TOTPGenerator.Builder builder;// = new TOTPGenerator.Builder(secret);
	static TOTPGenerator totp;// = builder.withPasswordLength(6).withAlgorithm(HMACAlgorithm.SHA1).build();
	
	static {
		byte[] secret = SecretGenerator.generate();
		builder = new TOTPGenerator.Builder(secret);
		totp = builder.withPasswordLength(6).withAlgorithm(HMACAlgorithm.SHA1).build();
	}
	
	public static void main(String[] args) {
		OTPService service = new OTPService();
		String code = service.generatorCode();
		boolean check = service.verify(code);
		System.out.println("check:"+check);
	}
	
	public String generatorCode() {
//		byte[] secret = SecretGenerator.generate();

		// Create a TOTPGenerate instance
//		TOTPGenerator.Builder builder = new TOTPGenerator.Builder(secret);
//		TOTPGenerator totp = builder.withPasswordLength(6).withAlgorithm(HMACAlgorithm.SHA1).build();

		try {
			String code = totp.generate();
			System.out.println("Generated code: " + code);

			// To verify a codes
//			boolean check = totp.verify(code); // true
//			System.out.println("check:" + check);
			return code;
		} catch (IllegalStateException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public boolean verify(String codeOTP) {
		return totp.verify(codeOTP);
	}
}
