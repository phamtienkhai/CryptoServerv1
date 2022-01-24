package com.kma.cs.utils.doc;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.ParserConfigurationException;

import org.openxml4j.exceptions.InvalidFormatException;
import org.openxml4j.exceptions.OpenXML4JException;
import org.openxml4j.opc.Package;
import org.openxml4j.opc.signature.PackageDigitalSignatureManager;
import org.openxml4j.opc.signature.VerifyResult;
import org.xml.sax.SAXException;

import com.kma.cs.utils.CryptoToken;
import com.kma.cs.utils.KeyStoreUtils;
//import com.groupdocs.signature.domain.Padding;
//import com.groupdocs.signature.domain.enums.HorizontalAlignment;
//import com.groupdocs.signature.domain.enums.VerticalAlignment;
//import com.groupdocs.signature.options.sign.DigitalSignOptions;
//import com.groupdocs.signature.*;
import com.spire.doc.Document;
import com.spire.doc.FileFormat;

public class DOCSigner {
	public static void main(String[] args) {
		String input, output, token, password;
		input = "D:\\KhaiPT\\file test\\sign\\docx\\docs\\filedocx.docx";
		output = "D:\\KhaiPT\\file test\\sign\\docx\\docs\\filedocx-output.docx";
		token = "F:\\khaipt.p12";
		password = "1";
		KeyStoreUtils utils = new KeyStoreUtils(token, password.toCharArray(), "PKCS12");
		CryptoToken cryptoToken = utils.getCryptoToken();
		DOCSigner docSigner = new DOCSigner();
//		byte[] dataSigned = docSigner.sign(input, cryptoToken);
//		try {
//			FileOutputStream os = new FileOutputStream(output);
//			os.write(dataSigned);
//		} catch (FileNotFoundException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//		Signature signature = new Signature("sample.docx");
//		DigitalSignOptions options = new DigitalSignOptions("certificate.pfx");
//
//		// certifiate password
//		options.setPassword("1234567890");
//		// digital certificate details
//		options.setReason("Sign");
//		options.setContact("JohnSmith");
//		options.setLocation("Office1");
//
//		// image as digital certificate appearance on document pages
//		options.setImageFilePath("sample.jpg");
//		//
//		options.setAllPages(true);
//		options.setWidth(80);
//		options.setHeight(60);
//		options.setVerticalAlignment(VerticalAlignment.Bottom);
//		options.setHorizontalAlignment(HorizontalAlignment.Right);
//		Padding padding = new Padding();
//		padding.setBottom(10);
//		padding.setRight(10);
//		options.setMargin(padding);
//
//		SignResult signResult = signature.sign("signed.docx", options);
//		// analyzing result
//		System.out.print("List of newly created signatures:");
//		int number = 1;
//		for (BaseSignature temp : signResult.getSucceeded()) {
//			System.out.print("Signature #" + number++ + ": Type: " + temp.getSignatureType() + " Id:"
//					+ temp.getSignatureId() + ",Location: " + temp.getLeft() + "x" + temp.getTop() + ". Size: "
//					+ temp.getWidth() + "x" + temp.getHeight());
//		}
//		catch (IOException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}

	}

	public byte[] sign(String input, CryptoToken cryptoToken, String algSig) {
		OOXMLSigner signer = new OOXMLSigner();
		String algDigest = "SHA256";
		if(algSig.contains("SHA1")) {
			algDigest = "SHA1";
		} else if(algSig.contains("SHA256")) {
			algDigest = "SHA256";
		} else if(algSig.contains("SHA384")) {
			algDigest = "SHA384";
		} else if(algSig.contains("SHA512")) {
			algDigest = "SHA512";
		}
		try {
			byte[] dataToSign = null;
			FileInputStream is = new FileInputStream(input);
			dataToSign = new byte[is.available()];
			is.read(dataToSign); is.close();
			byte[] dataSigned = signer.processData(dataToSign, cryptoToken, algSig, algDigest);
			return dataSigned;
		} catch(Exception ex) {
			ex.printStackTrace();
		}
		return null;
//		try {
//			FileInputStream is = new FileInputStream(input);
//			Package docxPackage = null;
//			docxPackage = Package.open(input);
//			PackageDigitalSignatureManager dsm = new PackageDigitalSignatureManager(docxPackage);
//			dsm.SignDocument(cryptoToken.getPrivateKey(), (X509Certificate) cryptoToken.getCert());
//			ByteArrayOutputStream os = new ByteArrayOutputStream();
//			dsm.getContainer().save(os);
//			return os.toByteArray();
//		} catch (FileNotFoundException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		} catch (InvalidFormatException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		} catch (IOException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		} catch (OpenXML4JException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//
//		return null;

	}
	
	public VerifyResult verify(String input) {
		try {
//			FileInputStream is = new FileInputStream(input);
			Package docxPackage = null;
			docxPackage = Package.open(input);
			PackageDigitalSignatureManager dsm = new PackageDigitalSignatureManager(docxPackage);
//			dsm.SignDocument(cryptoToken.getPrivateKey(), (X509Certificate) cryptoToken.getCert());
//			ByteArrayOutputStream os = new ByteArrayOutputStream();
//			dsm.getContainer().save(os);
//			return os.toByteArray();
			VerifyResult verifyResult =  dsm.VerifySignatures();
			return verifyResult;
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
		} catch (SAXException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ParserConfigurationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (MarshalException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (XMLSignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return null;

	}
}
