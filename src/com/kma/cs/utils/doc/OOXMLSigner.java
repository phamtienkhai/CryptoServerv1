package com.kma.cs.utils.doc;

import org.openxml4j.exceptions.InvalidFormatException;
import org.openxml4j.exceptions.OpenXML4JException;
import org.openxml4j.opc.PackageAccess;
import org.openxml4j.opc.signature.PackageDigitalSignatureManager;

import com.kma.cs.utils.CryptoToken;

import org.openxml4j.opc.Package;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public class OOXMLSigner {

	public static void main(String[] args) {
//        Security.addProvider(new XMLDSigRI());
		String aliase = "tupk_rsa";
		FileInputStream is = null;
		byte[] dataToSign = null;
		try {
			is = new FileInputStream("D:\\KhaiPT\\file test\\sign\\docx\\docs\\filedocx.docx");
			dataToSign = new byte[is.available()];
			is.read(dataToSign);
			is.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		String algSig = "SHA256withRSA";
		String digestSig = "SHA256";
		String providerName = "SunRsaSign";

//		OOXMLSigner signer = new OOXMLSigner();
//		byte[] dataSigned = signer.processData(aliase, dataToSign, algSig, digestSig, providerName);
//		System.out.println("dataSigned.length:" + dataSigned.length);
//		try {
//			FileOutputStream os = new FileOutputStream("D:\\KhaiPT\\file test\\sign\\docx\\docs\\filedocx-output.docx");
//			os.write(dataSigned);
//			os.close();
//		} catch (FileNotFoundException e) {
//			e.printStackTrace();
//		} catch (IOException e) {
//			e.printStackTrace();
//		}
	}

	public byte[] processData(byte[] data, CryptoToken cryptoToken, String algSig, String digestSig) {
//        KeyStore keyStore = KeyStoreUtils.getKeyStore(aliase, "123456", "D:\\khaipt.p12");
//		KeyStore keyStore = KeyStoreUtils.getKeyStore(aliase, "123456");
		try {
			PrivateKey privateKey = cryptoToken.getPrivateKey();
//            PrivateKey privateKey = (PrivateKey) keyStore.getKey(aliase, "123456".toCharArray());
			Certificate certificate = cryptoToken.getCert();
			X509Certificate certificate1 = (X509Certificate) certificate;
			byte[] dataSigned = sign(data, privateKey, certificate1, algSig, digestSig, "BC");
			return dataSigned;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public byte[] sign(byte[] dataToSign, PrivateKey privateKey, X509Certificate certificate, String algSig,
			String digestSig, String providerName) {
		try {
//            System.setProperty("javax.xml.parsers.DocumentBuilderFactory", "com.sun.org.apache.xerces.internal.jaxp.DocumentBuilderFactoryImpl");
//            FileInputStream is = new FileInputStream(input);
			ByteArrayInputStream is = new ByteArrayInputStream(dataToSign);
			Package docxPackage = null;
			docxPackage = Package.open(is, PackageAccess.READ_WRITE);
//            System.out.println("docxPackage.getPackageAccess().name():"+docxPackage.getPackageAccess().name());
			PackageDigitalSignatureManager dsm = new PackageDigitalSignatureManager(docxPackage);
			System.out.println("algSig:" + algSig);
			System.out.println("digestSig:" + digestSig);
			System.out.println("providerName:" + providerName);
			dsm.SignDocument(privateKey, certificate, algSig, digestSig, providerName);
			ByteArrayOutputStream os = new ByteArrayOutputStream();
			dsm.getContainer().save(os);
			byte[] dataSigned = os.toByteArray();
			System.out.println("dataSigned.length:" + dataSigned.length);
			return dataSigned;
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidFormatException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (OpenXML4JException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return null;
	}
}
