package com.kma.cs.utils.xml;

import com.kma.cs.utils.CryptoToken;
import com.kma.cs.utils.KeyStoreUtils;

import javax.xml.crypto.*;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dom.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.*;
import javax.xml.crypto.dsig.spec.*;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.binding.xmldsig.SignatureMethodType;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;


public class XMLSigner {
	public byte[] sign(String path, CryptoToken cryptoToken, String alg) {
		XMLSigner2 signer2 = new XMLSigner2();
		byte[] dataToSign2 = null;
		FileInputStream is;
		try {
			is = new FileInputStream(path);
			dataToSign2 = new byte[is.available()];
			is.read(dataToSign2); is.close();
		} catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}		
		byte[] dataSigned2 = signer2.processData(dataToSign2, cryptoToken, alg);
		if (dataSigned2 != null) {
			return dataSigned2;
		}
//		System.out.println("algSig:"+algSig);
		Security.addProvider(new BouncyCastleProvider());
		// Create a DOM XMLSignatureFactory that will be used to generate the
		// enveloped signature
		XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

		// Create a Reference to the enveloped document (in this case we are
		// signing the whole document, so a URI of "" signifies that) and
		// also specify the SHA256 digest algorithm and the ENVELOPED Transform.
		Reference ref = null;
		try {
			ref = fac.newReference("", fac.newDigestMethod(DigestMethod.SHA256, null),
					Collections.singletonList(fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)),
					null, null);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// Create the SignedInfo
		SignedInfo si = null;
		try {
			String algSig = "";
			System.out.println("alg:"+alg);
//			System.out.println(alg.contains("DSA"));
			if(alg.contains("EC")) {
//				algSig = "https://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1";
				algSig = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1";
				if(alg.contains("SHA1")) {
					algSig = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1";
				}
				else if(alg.contains("SHA224")) {
					algSig = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224";
				}
				else if(alg.contains("SHA256")) {
					algSig = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
				}
				else if(alg.contains("SHA384")) {
					algSig = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";
				}
				else if(alg.contains("SHA512")) {
					algSig = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512";
				}				
				
			} else if(alg.contains("RSA")) {
//				algSig = "https://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1";
				algSig = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
				if(alg.contains("SHA1")) {
					algSig = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
				}
				else if(alg.contains("SHA224")) {
					algSig = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha224";
				}
				else if(alg.contains("SHA256")) {
					algSig = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
				}
				else if(alg.contains("SHA384")) {
					algSig = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
				}
				else if(alg.contains("SHA512")) {
					algSig = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
				}						
			} else if(alg.contains("DSA")) {
				if(alg.contains("SHA1")) {
					algSig = "http://www.w3.org/2000/09/xmldsig#dsa-sha1";
				}
				else if(alg.contains("SHA224")) {
					algSig = "http://www.w3.org/2009/xmldsig11#dsa-sha256";
				}
			}
			System.out.println("algSig:"+algSig);//System.exit(0);
			si = fac.newSignedInfo(
					fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS,
							(C14NMethodParameterSpec) null),
					fac.newSignatureMethod(algSig, null),
					Collections.singletonList(ref));
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// Create a DSA KeyPair
//		KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
//		kpg.initialize(2048);
//		KeyPair kp = kpg.generateKeyPair();
		PrivateKey privateKey = cryptoToken.getPrivateKey();
		java.security.cert.Certificate cert = cryptoToken.getCert();

		List listCert = new ArrayList();
		listCert.add(cert);
		// Create a KeyValue containing the DSA PublicKey that was generated

		KeyInfoFactory kif = fac.getKeyInfoFactory();
//		KeyValue kv = kif.newKeyValue(kp.getPublic());
		List<XMLStructure> listStructures = new ArrayList<XMLStructure>();
		X509Data x509Data = kif.newX509Data(listCert);

		listStructures.add(x509Data);
		// Create a KeyInfo and add the KeyValue to it
		KeyInfo ki = kif.newKeyInfo(listStructures);

		// Instantiate the document to be signed
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		Document doc = null;
		try {
			doc = dbf.newDocumentBuilder().parse(new FileInputStream(path));
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SAXException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ParserConfigurationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// Create a DOMSignContext and specify the DSA PrivateKey and
		// location of the resulting XMLSignature's parent element
		DOMSignContext dsc = new DOMSignContext(privateKey, doc.getDocumentElement());

		// Create the XMLSignature (but don't sign it yet)
		XMLSignature signature = fac.newXMLSignature(si, ki);

		// Marshal, generate (and sign) the enveloped signature
		try {
			signature.sign(dsc);
		} catch (MarshalException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (XMLSignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// output the resulting document
		ByteArrayOutputStream os;
//		if (args.length > 1) {
		os = new ByteArrayOutputStream();
//		} else {
//			os = System.out;
//		}

		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer trans = null;
		try {
			trans = tf.newTransformer();
			trans.transform(new DOMSource(doc), new StreamResult(os));
		} catch (TransformerConfigurationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (TransformerException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return os.toByteArray();
	}

	public static void main(String[] args) {
//		KeyStoreUtils keyStoreUtils = new KeyStoreUtils("F:\\khaipt.p12", "1".toCharArray(), "PKCS12");
//		CryptoToken cryptoToken = keyStoreUtils.getCryptoToken();
//		String path = "F:\\loz.xml";
//		XMLSigner xmlSigner = new XMLSigner();
//		byte[] dataSigned = xmlSigner.sign(path, cryptoToken, "cryptoToken");
//		try {
//			FileOutputStream os = new FileOutputStream("F:\\loz-output.xml");
//			os.write(dataSigned);
//			os.close();
//		} catch (FileNotFoundException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		} catch (IOException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//		System.out.println(SignatureMethod.RSA_SHA1);
		XMLSigner signer = new XMLSigner();
		signer.sign(null, null, "SHA1WithDSA");
	}
}
