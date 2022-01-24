package com.kma.cs.utils.xml;

import javax.xml.crypto.*;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dom.*;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.*;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

//import org.openxml4j.opc.signature.digest.SignatureMethod;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public class XMLValidator {

	public static void main(String[] args) throws Exception {
		XMLValidator validator = new XMLValidator();
		boolean validator2 = validator.validator("F:\\loz-output.xml");
		System.out.println("validator:"+validator2);
	}

	public boolean validator(String path) {
		// Instantiate the document to be validated
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

		// Find Signature element
		NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
		if (nl.getLength() == 0) {
			System.out.println("Khong tim thay chu ky");
			
		}

		// Create a DOM XMLSignatureFactory that will be used to unmarshal the
		// document containing the XMLSignature
		XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

		// Create a DOMValidateContext and specify a KeyValue KeySelector
		// and document context
		DOMValidateContext valContext = new DOMValidateContext(new KeyValueKeySelector(), nl.item(0));

		// unmarshal the XMLSignature
		XMLSignature signature = null;
		try {
			signature = fac.unmarshalXMLSignature(valContext);
		} catch (MarshalException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// Validate the XMLSignature (generated above)
		boolean coreValidity = false;
		try {
			coreValidity = signature.validate(valContext);
			if (!coreValidity)
				return false;
		} catch (XMLSignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// Check core validation status
		if (coreValidity == false) {
			System.err.println("Signature failed core validation");
			boolean sv = false;
			try {
				sv = signature.getSignatureValue().validate(valContext);
				if (!sv)
					return false;
			} catch (XMLSignatureException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			System.out.println("signature validation status: " + sv);
			// check the validation status of each Reference
			Iterator i = signature.getSignedInfo().getReferences().iterator();
			for (int j = 0; i.hasNext(); j++) {
				boolean refValid = false;
				try {
					refValid = ((Reference) i.next()).validate(valContext);
					if (!refValid)
						return false;
				} catch (XMLSignatureException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				System.out.println("ref[" + j + "] validity status: " + refValid);
			}
		} else {
			System.out.println("Signature passed core validation");
			return true;
		}
		return false;
	}

	private static class KeyValueKeySelector extends KeySelector {
		public KeySelectorResult select(KeyInfo keyInfo, KeySelector.Purpose purpose, AlgorithmMethod method,
				XMLCryptoContext context) throws KeySelectorException {
			if (keyInfo == null) {
				throw new KeySelectorException("Null KeyInfo object!");
			}
			SignatureMethod sm = (SignatureMethod) method;
			List list = keyInfo.getContent();

			for (int i = 0; i < list.size(); i++) {
				XMLStructure xmlStructure = (XMLStructure) list.get(i);
				if (xmlStructure instanceof X509Data) {
					PublicKey pk = null;
//					Certificate cert = null;
//					X509Data x509Data = xmlStructure.getContent();
					X509Data x509Data = (X509Data) xmlStructure;
					X509Certificate cert = (X509Certificate) x509Data.getContent().get(0);
					pk = cert.getPublicKey();
					System.out.println(cert.getSubjectDN());
					System.out.println(cert.getPublicKey().getAlgorithm());
//					pk = ((X509Data) xmlStructure).getContent();
					// make sure algorithm is compatible with method
					if (algEquals(sm.getAlgorithm(), pk.getAlgorithm())) {
						return new SimpleKeySelectorResult(pk);
					}
				}
			}
			throw new KeySelectorException("No KeyValue element found!");
		}

		static boolean algEquals(String algURI, String algName) {
			System.out.println(algURI);
			System.out.println(algName);
			if (algName.equalsIgnoreCase("DSA")) {
				if(algURI.equalsIgnoreCase(SignatureMethod.DSA_SHA1) || algURI.equalsIgnoreCase(org.openxml4j.opc.signature.digest.SignatureMethod.DSA_SHA256) || algURI.equalsIgnoreCase(org.openxml4j.opc.signature.digest.SignatureMethod.DSA_SHA384) || algURI.equalsIgnoreCase(org.openxml4j.opc.signature.digest.SignatureMethod.DSA_SHA512)) {
					return true;
				}
				return false;
			} else if (algName.equalsIgnoreCase("RSA")) {
				if(algURI.equalsIgnoreCase(SignatureMethod.RSA_SHA1) || algURI.equalsIgnoreCase(org.openxml4j.opc.signature.digest.SignatureMethod.RSA_SHA256) || algURI.equalsIgnoreCase(org.openxml4j.opc.signature.digest.SignatureMethod.RSA_SHA384) || algURI.equalsIgnoreCase(org.openxml4j.opc.signature.digest.SignatureMethod.RSA_SHA512)) {
					return true;
				}
				return false;
			} else if (algName.equalsIgnoreCase("ECDSA")) {
				if(algURI.equalsIgnoreCase(org.openxml4j.opc.signature.digest.SignatureMethod.ECDSA_SHA1) || algURI.equalsIgnoreCase(org.openxml4j.opc.signature.digest.SignatureMethod.ECDSA_SHA256) || algURI.equalsIgnoreCase(org.openxml4j.opc.signature.digest.SignatureMethod.ECDSA_SHA384) || algURI.equalsIgnoreCase(org.openxml4j.opc.signature.digest.SignatureMethod.ECDSA_SHA512)) {
					return true;
				}
				return false;
			} else {
				return false;
			}
		}
	}

	private static class SimpleKeySelectorResult implements KeySelectorResult {
		private PublicKey pk;

		SimpleKeySelectorResult(PublicKey pk) {
			this.pk = pk;
		}

		public Key getKey() {
			return pk;
		}
	}
}
