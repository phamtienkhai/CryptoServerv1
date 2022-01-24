package com.kma.cs.utils.pdf;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.signatures.PdfPKCS7;
import com.itextpdf.signatures.SignatureUtil;

public class PDFValidator {
	public boolean validator(byte[] data) {
		Security.addProvider(new BouncyCastleProvider());
		ByteArrayInputStream is = new ByteArrayInputStream(data);
		PdfReader reader = null;
		try {
			reader = new PdfReader(is);
			PdfDocument pdfDoc = new PdfDocument(reader);
			SignatureUtil signUtil = new SignatureUtil(pdfDoc);
			List<String> names = signUtil.getSignatureNames();
			boolean check = false;
			for(String name : names) {
				System.out.println("name:"+name);
				PdfPKCS7 pkcs7 = signUtil.readSignatureData(name);//pkcs7.
				check = pkcs7.verifySignatureIntegrityAndAuthenticity();
			}
			return check;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (GeneralSecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
	}
}
