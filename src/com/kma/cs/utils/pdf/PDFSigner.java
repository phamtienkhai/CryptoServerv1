package com.kma.cs.utils.pdf;

import com.itextpdf.io.image.ImageData;
import com.itextpdf.io.image.ImageDataFactory;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.IExternalDigest;
import com.itextpdf.signatures.IExternalSignature;
import com.itextpdf.signatures.PdfSignatureAppearance;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.PdfSigner.CryptoStandard;
import com.itextpdf.signatures.PrivateKeySignature;
import com.kma.cs.utils.CryptoToken;
import com.spire.pdf.PdfDocument;
import com.spire.pdf.graphics.PdfFont;
import com.spire.pdf.graphics.PdfFontFamily;
import com.spire.pdf.graphics.PdfFontStyle;
import com.spire.pdf.graphics.PdfImage;
import com.spire.pdf.security.GraphicMode;
import com.spire.pdf.security.PdfCertificate;
import com.spire.pdf.security.PdfCertificationFlags;
import com.spire.pdf.security.PdfSignature;
import com.spire.pdf.security.SignImageLayout;
import com.spire.pdf.security.SignTextAlignment;

import java.awt.*;
import java.awt.geom.Point2D;
import java.awt.geom.Rectangle2D;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;

import org.openxml4j.opc.PackageAccess;
import org.openxml4j.opc.signature.PackageDigitalSignatureManager;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.openxml4j.exceptions.InvalidFormatException;
import org.openxml4j.exceptions.OpenXML4JException;
import org.openxml4j.opc.Package;

import com.spire.pdf.PdfDocument;
import com.spire.pdf.security.PdfSignature;
import com.spire.pdf.widget.*;
import com.itextpdf.kernel.geom.Rectangle;

public class PDFSigner {
	public static void main(String[] args) {
		PDFSigner pdfSigner = new PDFSigner();
		String input, output, image, token, password;
		input = "D:\\KhaiPT\\file test\\sign\\pdf\\filepdf.pdf";
		output = "D:\\KhaiPT\\file test\\sign\\pdf\\filepdf-output.pdf";
		image = "D:\\KhaiPT\\file test\\sign\\pdf\\khaipt.jpg";
		token = "D:\\rsa.p12";
		password = "123456";
		pdfSigner.sign(input, output, image, token, password, "Pham Tien Khai vip pro");
//		pdfSigner.validator(output);
	}

	public void sign(String input, String output, String image, String token, String password, String userName) {
		// Load a pdf document
		PdfDocument doc = new PdfDocument();
//		doc.loadFromFile("D:\\KhaiPT\\file test\\sign\\pdf\\filepdf.pdf");
		doc.loadFromFile(input);

		// Load the certificate
//		System.out.println("token:"+token);
//		System.out.println("password:"+password);
		PdfCertificate cert = new PdfCertificate(token, password);

		// Create a PdfSignature object and specify its position and size
		PdfSignature signature = new PdfSignature(doc, doc.getPages().get(0), cert, "MySignature");
//				new PdfSignature(null, cert, null);
		Rectangle2D rect = new Rectangle2D.Float();
		rect.setFrame(new Point2D.Float((float) doc.getPages().get(0).getActualSize().getWidth() - 320,
				(float) doc.getPages().get(0).getActualSize().getHeight() - 140), new Dimension(270, 100));
		signature.setBounds(rect);

		// Set the graphics mode
		signature.setGraphicMode(GraphicMode.Sign_Image_And_Sign_Detail);

		// Set the signature content
//				signature.setNameLabel("Signer:");
//				signature.setName("Gary");
		signature.setNameLabel("Signer:");
//		signature.setName("Pham Tien Khai");
		signature.setName(userName);
//				signature.setContactInfoLabel("ContactInfo:");
//				signature.setContactInfo("02881705109");
		signature.setDateLabel("Date:");
		signature.setDate(new java.util.Date());
//		signature.set
//				signature.setLocationInfoLabel("Location:");
//				signature.setLocationInfo("Chengdu");
//				signature.setReasonLabel("Reason: ");
//				signature.setReason("The certificate of this document");
//				signature.setDistinguishedNameLabel("DN: ");
//				signature.setDistinguishedName(signature.getCertificate().get_IssuerName().getName());
//				String nguoiky, ngayky;
//				nguoiky = "Pham Tien Khai";
//				Date date = Calendar.getInstance().getTime();
//				DateFormat dateFormat = new SimpleDateFormat("yyyy-mm-dd hh:mm:ss");
//				String strDate = dateFormat.format(date);
//				ngayky = strDate;
//				String text = "Nguoi ky:\n" + nguoiky + "\nNgay ky:\n" + ngayky;
//				signature.setContactInfo(new String(text.getBytes(), StandardCharsets.UTF_8));
		signature.setSignImageSource(PdfImage.fromFile(image));
//				SignImageLayout.
		signature.setSignImageLayout(SignImageLayout.Stretch);
		signature.setCustomSignImagePosition((float) doc.getPages().get(0).getActualSize().getWidth() - 320,
				(float) doc.getPages().get(0).getActualSize().getHeight() - 140, (float) 100, (float) 100);
//				signature.setSignIma
//				PdfImage.fromImage(null, true);
//				signature.setSignIm

		// Set the signature font
//				signature.setSignTextAlignment(SignTextAlignment.);
//				signature.setSignDetailsFont(null);
		signature.setSignDetailsFont(new PdfFont(PdfFontFamily.Helvetica, 10f, PdfFontStyle.Regular));

		// Set the document permission
		signature.setDocumentPermissions(PdfCertificationFlags.Forbid_Changes);
		signature.setCertificated(true);

		// Save to file
//		doc.saveToFile("D:\\KhaiPT\\file test\\sign\\pdf\\filepdf-output.pdf");
		doc.saveToFile(output);
		doc.close();
	}
	
	public byte[] processData(byte[] dataToSign, CryptoToken cryptoToken, String digestAlgorithm, String image) {
		try {
			Provider provider = Security.getProvider("BC");
			if(provider == null) {
				Security.addProvider(new BouncyCastleProvider());
			}
			System.out.println("digestAlgorithm:"+digestAlgorithm);//System.exit(0);
			byte[] dataSigned = null;
			PrivateKey privateKey = cryptoToken.getPrivateKey();
			Certificate[] chain = cryptoToken.getCertChain();
			digestAlgorithm = getDigestFromSigAlg(digestAlgorithm);
			X509Certificate certificate = (X509Certificate)cryptoToken.getCert();
//			System.out.println(certificate.getSubjectDN());
			Date date = Calendar.getInstance().getTime();
			DateFormat dateFormat = new SimpleDateFormat("yyyy-mm-dd hh:mm:ss");  
            String strDate = dateFormat.format(date);  
			String text = "Nguoi ky: " + certificate.getSubjectDN().getName() + "\n Ngay ky: " + strDate;
			dataSigned = sign2(dataToSign, privateKey, chain, digestAlgorithm, "BC", CryptoStandard.CMS, text, image);
			return dataSigned;
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return null;
	}

	public byte[] sign2(byte[] dataToSign, PrivateKey privateKey, Certificate[] chain, String digestAlgorithm,
			String provider, PdfSigner.CryptoStandard signatureType, String text, String image) {
		try {
			ByteArrayOutputStream os = new ByteArrayOutputStream();
			ByteArrayInputStream is = new ByteArrayInputStream(dataToSign);
			PdfReader reader = new PdfReader(is);

// reader = new PdfReader()
//PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest), new StampingProperties());
			PdfSigner signer = new PdfSigner(reader, os, new StampingProperties());

// PdfWriter writer = new PdfWriter(new ByteArrayOutputStream());
// PdfDocument pdfDocument = new PdfDocument(reader, writer, new StampingProperties(new StampingProperties()).preserveEncryption());
// System.out.println("pdfDocument.getNumberOfPages():"+pdfDocument.getNumberOfPages());
// System.exit(0);
			// Create the signature appearance
			Rectangle rect = new Rectangle(300, 100, 200, 100);
			PdfSignatureAppearance appearance = signer.getSignatureAppearance();
//appearance
//     .setReason(reason)
//     .setLocation(location)

			// Specify if the appearance before field is signed will be used
			// as a background for the signed field. The "false" value is the default value.
//     .setReuseAppearance(false)
//     .setPageRect(rect)
//     .setPageNumber(1);
			appearance.setPageNumber(1);
			appearance.setPageRect(rect);
			appearance.setLayer2FontSize(12);
// String text = "Chó cũng là loài động vật đầu tiên được con người thuần hóa[12][13] và đã được chọn giống qua hàng thiên niên kỷ với nhiều hành vi, khả năng cảm nhận và đặc tính vật lý.[14] Loài vật này được sử dụng để giữ nhà hoặc làm thú chơi. Răng của chúng dùng để giết mồi, nhai thịt và gặm thịt, thỉnh thoảng để cắn nhau. Chó là loài động vật được nuôi nhiều trên thế giới, có thể trông coi nhà, chăn cừu, dẫn đường, kéo xe, cũng là thực phẩm giàu đạm. Chó giúp con người rất nhiều việc như trông nhà cửa, săn bắt, và được xem như là loài vật trung thành, tình nghĩa nhất với con người. Ngày nay, nhu cầu nuôi chó cảnh đang được phát triển nên những giống chó nhỏ như Fox, Chihuahua hoặc chó thông minh như Collie được nhiều người chơi quan tâm đến.Chó cũng là loài động vật đầu tiên được con người thuần hóa[12][13] và đã được chọn giống qua hàng thiên niên kỷ với nhiều hành vi, khả năng cảm nhận và đặc tính vật lý.[14] Loài vật này được sử dụng để giữ nhà hoặc làm thú chơi. Răng của chúng dùng để giết mồi, nhai thịt và gặm thịt, thỉnh thoảng để cắn nhau. Chó là loài động vật được nuôi nhiều trên thế giới, có thể trông coi nhà, chăn cừu, dẫn đường, kéo xe, cũng là thực phẩm giàu đạm. Chó giúp con người rất nhiều việc như trông nhà cửa, săn bắt, và được xem như là loài vật trung thành, tình nghĩa nhất với con người. Ngày nay, nhu cầu nuôi chó cảnh đang được phát triển nên những giống chó nhỏ như Fox, Chihuahua hoặc chó thông minh như Collie được nhiều người chơi quan tâm đến.";
			text = new String(text.getBytes(StandardCharsets.UTF_8));
			appearance.setText(text);
//PdfFont pdfFont = PdfFontFactory.create
//appearance.setLayer2Font()
//appearance.setT

			byte[] imageBytes = java.util.Base64.getDecoder().decode(image.getBytes());
// ImageData imageData = ImageDataFactory.create("D:\\chukytay.jpg");
			ImageData imageData = ImageDataFactory.create(imageBytes);
			appearance.setImage(imageData);
			appearance.setSignatureGraphic(imageData);
			appearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.DESCRIPTION);
			signer.setFieldName("sig");

			IExternalSignature pks = new PrivateKeySignature(privateKey, digestAlgorithm, provider);
			IExternalDigest digest = new BouncyCastleDigest();

			// Sign the document using the detached mode, CMS or CAdES equivalent.
			signer.signDetached(digest, pks, chain, null, null, null, 0, signatureType);

			byte[] dataSigned = os.toByteArray();
//			System.out.println("dataSigned.length:" + dataSigned.length);
// FileOutputStream fos = new FileOutputStream(dest);
// fos.write(dataSigned);
// fos.close();
			return dataSigned;
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return null;
	}

	public boolean validator(String input) {
		try {
			boolean check = false;
			byte[] data = null;
			FileInputStream is = new FileInputStream(input);
			data = new byte[is.available()];
			is.read(data); is.close();
			PDFValidator validator = new PDFValidator();
			check = validator.validator(data);
			return check;
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
		// Load a pdf document
//		PdfDocument doc = new PdfDocument();
//		doc.loadFromFile(input);
//
//		// Get the collection of PDF fields
//		PdfFormWidget pdfFormWidget = (PdfFormWidget) doc.getForm();
//		PdfFormFieldWidgetCollection pdfFormFieldWidgetCollection = pdfFormWidget.getFieldsWidget();
//
//		// Traverse all the PDF form field
//		for (int i = 0; i < pdfFormFieldWidgetCollection.getCount(); i++) {
//			// check whether it is PdfSignatureField
//			if (pdfFormFieldWidgetCollection.get(i) instanceof PdfSignatureFieldWidget) {
//				// get the signature field
//				PdfSignatureFieldWidget signatureFieldWidget = (PdfSignatureFieldWidget) pdfFormFieldWidgetCollection
//						.get(i);
//				// get the PDF signature
//				PdfSignature signature = signatureFieldWidget.getSignature();
//
//				// Verify the signature
//				boolean result = signature.verifySignature();
//				if (result) {
//					System.out.println("Valid signature");
////					return true;
//				} else {
//					System.out.println("Invalid signature");
//				}
//				return result;
//			}
//		}
//		return false;
	}
	
	public String getDigestFromSigAlg(String sigAlg) {
		//1-224/-256-384-512
		if(sigAlg.contains("SHA1")) {
			return "SHA1";
		} else if(sigAlg.contains("SHA256")) {
			return "SHA256";
		} else if(sigAlg.contains("SHA224")) {
			return "SHA224";
		} else if(sigAlg.contains("SHA384")) {
			return "SHA384";
		} else if(sigAlg.contains("SHA512")) {
			return "SHA512";
		} 
		return "SHA256";
	}
}
