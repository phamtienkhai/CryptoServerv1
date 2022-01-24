package com.kma.cs.utils.mail;

import java.util.Properties;

import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

import com.kma.cs.utils.otp.OTPService;

public class SendMail {
	public static void main(String[] args) {
		String fromMail, passwordFromMail, toMail, codeOTP;
		OTPService service = new OTPService();
		codeOTP = service.generatorCode();
		fromMail = "chusau7mau@gmail.com";
		passwordFromMail = "chusau7maua@A123z!";
		toMail = "khaihackerqsc@gmail.com";
		SendMail sendMail = new SendMail();
//		sendMail.send(fromMail, passwordFromMail, toMail, codeOTP);
		boolean check = service.verify(codeOTP);
		System.out.println("check:"+check);
	}

	public void send(String fromMail, String passwordFromMail, String toMail, String codeOTP) {
		// Recipient's email ID needs to be mentioned.
//		String to = "chusau7mau@gmail.com";

		// Sender's email ID needs to be mentioned
//		String from = "khaihackerqsc@gmail.com";

		// Assuming you are sending email from through gmails smtp
		String host = "smtp.gmail.com";

		// Get system properties
		Properties properties = System.getProperties();

		// Setup mail server
		properties.put("mail.smtp.host", host);
		properties.put("mail.smtp.port", "465");
		properties.put("mail.smtp.ssl.enable", "true");
		properties.put("mail.smtp.auth", "true");
		properties.put("imap.smtp.com", "imap.gmail.com");
		properties.put("imap.smtp.ssl.enable", "true");
		properties.put("imap.smtp.port", "993");

		// Get the Session object.// and pass username and password
		Session session = Session.getInstance(properties, new javax.mail.Authenticator() {

			protected PasswordAuthentication getPasswordAuthentication() {

//				return new PasswordAuthentication("chusau7mau@gmail.com", "chusau7maua@A123z!");
				return new PasswordAuthentication(fromMail, passwordFromMail);

			}

		});

		// Used to debug SMTP issues
		session.setDebug(true);

		try {
			// Create a default MimeMessage object.
			MimeMessage message = new MimeMessage(session);

			// Set From: header field of the header.
//					message.setFrom(new InternetAddress(from));
			message.setFrom(new InternetAddress(fromMail));

			// Set To: header field of the header.
//					message.addRecipient(Message.RecipientType.TO, new InternetAddress(to));
			message.addRecipient(Message.RecipientType.TO, new InternetAddress(toMail));

			// Set Subject: header field
//					message.setSubject("This is the Subject Line!");
//			message.setSubject("Hello!");
			message.setSubject("CryptoService OTP");

			// Now set the actual message
//					message.setText("This is actual message");
//			message.setText("An com chua the");
			message.setText("Mã OTP:"+codeOTP);

			System.out.println("sending...");
			// Send message
			Transport.send(message);
			System.out.println("Sent message successfully....");
		} catch (MessagingException mex) {
			mex.printStackTrace();
		}

	}
}
