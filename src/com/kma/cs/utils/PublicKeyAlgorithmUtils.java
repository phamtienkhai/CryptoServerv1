package com.kma.cs.utils;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.Random;
import java.util.Vector;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;

import javax.security.auth.x500.X500Principal;

import sun.security.pkcs10.*;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.*;

public class PublicKeyAlgorithmUtils {

	private static PrivateKey privateKey;

	public static PublicKey publicKey;

	private static final String providerBC = "BC";

	public static PrivateKey getPrivateKey() {
		return privateKey;
	}

	public static void setPrivateKey(PrivateKey privateKey) {
		PublicKeyAlgorithmUtils.privateKey = privateKey;
	}

	public static PrivateKey genKey(String algorithm, int size) {
		Security.addProvider(new BouncyCastleProvider());
		try {
//			String 
			KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm, "BC");
			kpg.initialize(size);
			KeyPair kp = kpg.generateKeyPair();
			privateKey = kp.getPrivate();
			publicKey = kp.getPublic();
			return privateKey;
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	public static byte[] encryptData(String algorithm, byte[] dataToEncrypt, PublicKey publicKey) {
		try {
			Cipher cipher = Cipher.getInstance(algorithm, "BC");
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			cipher.update(dataToEncrypt);
			byte[] dataEncrypt = cipher.doFinal();
			return dataEncrypt;
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

	public static byte[] decryptData(String algorithm, byte[] dataEncrypt, PrivateKey privateKey) {
		try {
			Cipher cipher = Cipher.getInstance(algorithm, "BC");
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			cipher.update(dataEncrypt);
			byte[] plainText = cipher.doFinal();
			return plainText;
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

	public static byte[] signData(String algorithm, byte[] dataToSign, PrivateKey privateKey) {
		try {
			Signature signature = Signature.getInstance(algorithm, "BC");
			signature.initSign(privateKey);
			signature.update(dataToSign);
			byte[] dataSigner = signature.sign();
			return dataSigner;
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	public static boolean signData(String algorithm, byte[] dataToSign, PublicKey publicKey, byte[] dataSigner) {
		try {
			Signature signature = Signature.getInstance(algorithm, "BC");
			signature.initVerify(publicKey);
			signature.update(dataToSign);
			boolean checkDS = signature.verify(dataSigner);
			return checkDS;
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
	}

	public static byte[] hashFunctions(String algorithm, byte[] dataToHash) {
		try {
			MessageDigest md = MessageDigest.getInstance(algorithm, "BC");
			md.update(dataToHash);
			return md.digest();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	public static byte[] genRandomString(int size) {
		byte[] array = new byte[size]; // length is bounded by 7
		new Random().nextBytes(array);
		String generatedString = new String(array, Charset.forName("UTF-8"));

//	    System.out.println(generatedString);
//	    return generatedString;
		return array;
	}

	public static SecretKeySpec genSecretKey(byte[] secretKey, String algorithm) {
		SecretKeySpec sks = new SecretKeySpec(secretKey, "HmacSHA256");
		return sks;
	}

	public static byte[] hmacFunctions(String algorithm, byte[] dataToHMAC, String key, byte[] message) {
		try {
			Mac mac = Mac.getInstance(algorithm, providerBC);
			SecretKeySpec sks = genSecretKey("secretKey".getBytes("UTF-8"), algorithm);
			mac.init(sks);
			mac.update(message);
			byte[] hmac = mac.doFinal();
			return hmac;
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	public static byte[] generatePKCS10(String CN, String OU, String O, String L, String S, String C) throws Exception {
		String sigAlg = "SHA1WithRSA";
		PKCS10 pkcs10 = new PKCS10(publicKey);
		Signature signature = Signature.getInstance(sigAlg);
		signature.initSign(privateKey);
		String format = "CN=%s,C=%s";
		format = String.format(format, CN, C);
		System.out.println("format:" + format);
		X500Principal principal = new X500Principal(format);
		X500Name x500name = null;
		x500name = new X500Name(principal.getEncoded());
		pkcs10.encodeAndSign(x500name, signature);
		ByteArrayOutputStream bs = new ByteArrayOutputStream();
		PrintStream ps = new PrintStream(bs);
		pkcs10.print(ps);
		byte[] c = bs.toByteArray();
		try {
			if (ps != null)
				ps.close();
			if (bs != null)
				bs.close();
		} catch (Throwable th) {
		}
		bs.close();
		System.out.println(new String(c));// System.exit(0);
		String csrStr = new String(c);
		String csrStrStart = "-----BEGIN NEW CERTIFICATE REQUEST-----";
		String csrStrEnd = "-----END NEW CERTIFICATE REQUEST-----";
		return csrStr.substring(csrStrStart.length() + 2, csrStr.length() - csrStrEnd.length() - 2).trim().getBytes();
	}

	public static java.security.cert.Certificate[] genCertificate(String newAlias, String password2, String userName) {
		String keystoreFile = "C:\\Users\\ptkat\\OneDrive\\Desktop\\rootca.jks";
		String caAlias = "rootca";

		char[] password = new char[] { '1' };
		char[] caPassword = new char[] { '1' };
		char[] certPassword = new char[] { '1' };
		certPassword = password2.toCharArray();

		FileInputStream input = null;

		try {
			input = new FileInputStream(keystoreFile);
			KeyStore keyStore = KeyStore.getInstance("JKS");
			keyStore.load(input, password);

			PrivateKey caPrivateKey = (PrivateKey) keyStore.getKey(caAlias, caPassword);
			java.security.cert.Certificate caCert = keyStore.getCertificate(caAlias);

			byte[] encoded = caCert.getEncoded();
			X509CertImpl caCertImpl = new X509CertImpl(encoded);

			X509CertInfo caCertInfo = (X509CertInfo) caCertImpl.get(X509CertImpl.NAME + "." + X509CertImpl.INFO);

			X500Name issuer = new X500Name("CN=RootCA, C=VN");
			X500Name subject = new X500Name("CN=" + userName + ", C=VN");

			X509CertInfo certInfo = new X509CertInfo();
			Date firstDate = new Date();
			Date lastDate = new Date(firstDate.getTime() + 365 * 24 * 60 * 60 * 1000L);
			CertificateValidity interval = new CertificateValidity(firstDate, lastDate);

			certInfo.set(X509CertInfo.VALIDITY, interval);
			certInfo.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(11111));
			certInfo.set(X509CertInfo.ISSUER + "." + CertificateSubjectName.DN_NAME, issuer);
			certInfo.set(X509CertInfo.SUBJECT + "." + CertificateSubjectName.DN_NAME, subject);
			certInfo.set(X509CertInfo.KEY, new CertificateX509Key(publicKey));
			certInfo.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));

			CertificateExtensions certificateExtensions = new CertificateExtensions();
			KeyUsageExtension keyUsageExtension = new KeyUsageExtension();
			keyUsageExtension.set(KeyUsageExtension.DIGITAL_SIGNATURE, true);
			keyUsageExtension.set(KeyUsageExtension.NON_REPUDIATION, true);
			keyUsageExtension.set(KeyUsageExtension.DATA_ENCIPHERMENT, true);
			keyUsageExtension.set(KeyUsageExtension.KEY_AGREEMENT, true);
			keyUsageExtension.set(KeyUsageExtension.KEY_CERTSIGN, true);
			keyUsageExtension.set(KeyUsageExtension.CRL_SIGN, true);
			certificateExtensions.set(KeyUsageExtension.IDENT, keyUsageExtension);

			Vector<ObjectIdentifier> extendedKeyUsageExtensionList = new Vector<ObjectIdentifier>();
			extendedKeyUsageExtensionList.add(new ObjectIdentifier("1.3.6.1.5.5.7.3.1"));
			extendedKeyUsageExtensionList.add(new ObjectIdentifier("1.3.6.1.5.5.7.3.2"));
			extendedKeyUsageExtensionList.add(new ObjectIdentifier("1.3.6.1.5.5.7.3.3"));
			extendedKeyUsageExtensionList.add(new ObjectIdentifier("1.3.6.1.5.5.7.3.4"));
			extendedKeyUsageExtensionList.add(new ObjectIdentifier("1.3.6.1.5.5.7.3.5"));
			extendedKeyUsageExtensionList.add(new ObjectIdentifier("1.3.6.1.5.5.7.3.6"));
			extendedKeyUsageExtensionList.add(new ObjectIdentifier("1.3.6.1.5.5.7.3.7"));
			extendedKeyUsageExtensionList.add(new ObjectIdentifier("1.3.6.1.5.5.7.3.8"));
			extendedKeyUsageExtensionList.add(new ObjectIdentifier("1.3.6.1.5.5.7.3.9"));

			ExtendedKeyUsageExtension extendedKeyUsageExtension = new ExtendedKeyUsageExtension(true,
					extendedKeyUsageExtensionList);
			certificateExtensions.set(ExtendedKeyUsageExtension.IDENT, extendedKeyUsageExtension);
			certInfo.set(X509CertInfo.EXTENSIONS, certificateExtensions);

			AlgorithmId algorithm = new AlgorithmId(AlgorithmId.sha256WithRSAEncryption_oid);
			CertificateAlgorithmId certificateAlgorithmId = new CertificateAlgorithmId(algorithm);
			certInfo.set(X509CertInfo.ALGORITHM_ID, certificateAlgorithmId);

			X509CertImpl newCert = new X509CertImpl(certInfo);

			newCert.sign(caPrivateKey, "SHA256WithRSA");

			keyStore.setKeyEntry(newAlias, privateKey, certPassword, new java.security.cert.Certificate[] { newCert });

			return new java.security.cert.Certificate[] { newCert };
//			FileOutputStream output = new FileOutputStream(keystoreFile);
//			keyStore.store(output, password);
//			
//			KeyStore keyStore2 = KeyStore.getInstance("PKCS12");
//			keyStore2.load(null, null);
//			keyStore2.setKeyEntry("khaipt", privateKey, "1".toCharArray(), new java.security.cert.Certificate[] { newCert });
//			keyStore2.store(new FileOutputStream("F:\\khaipt.p12"), "1".toCharArray());
//			output.close();

		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
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
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return null;
	}

	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());
		genKey("RSA", 2048);

		try {
			byte[] csr = generatePKCS10("KhaiPT", "", "", "", "", "VN");
			PKCS10CertificationRequest pkcs10 = new PKCS10CertificationRequest(csr);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
