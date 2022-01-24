/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.kma.cs.view;

import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.util.List;

import javax.crypto.SecretKey;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;

import com.kma.cs.model.AlgorithmCrypto;
import com.kma.cs.model.DatabaseCRUD;
import com.kma.cs.utils.KeyStoreUtils;
import com.kma.cs.utils.PublicKeyAlgorithmUtils;
import com.kma.cs.utils.SecretKeyAlgorithmUtils;
import java.awt.Font;

/**
 *
 * @author ptkat
 */
public class GenerateKey extends javax.swing.JFrame {

	private static String pathKeyStore;
	private static String password;
	private static String algorithmName;
	private static String size;
	private static String type;
	private static List listAlgorithmCryptoAll;
	private String userName2;

	public void setUsername2(String userName2) {
		this.userName2 = userName2;
	}

	public GenerateKey() {
		initComponents();
		Font font = new Font("SansSerif", Font.PLAIN, 25);
        jButton_Cipher.setFont(font);
        jButton_File.setFont(font);
        jButton_GenerateKey.setFont(font);
        jButton_Signature.setFont(font);
        jComboBox_Algorithm.setFont(font);
        jComboBox_Size.setFont(font);
        jLabel_Algorithm.setFont(font);
        jLabel_File.setFont(font);
        jLabel_Password.setFont(font);
        jLabel_Size.setFont(font);
        jTextField_File.setFont(font);
        jPasswordField_Password.setFont(font);
        this.setTitle("Generate Key");
		
		List listAlgorithmCrypto = DatabaseCRUD.getTable("select * from algorithmcrypto", "algorithmcrypto");
//      List listAlgorithmCrypto = DatabaseCRUD.getTable("select * from algorithmcrypto", "algorithmcrypto");
		listAlgorithmCryptoAll = listAlgorithmCrypto;
		for (Object object : listAlgorithmCrypto) {
//      	System.out.println(ob);
			AlgorithmCrypto algorithmCrypto = (AlgorithmCrypto) object;
			jComboBox_Algorithm.addItem(algorithmCrypto.getAlgorithmName());
		}
		this.setLocation(400, 150);
//		this.setSize(1000, 500);
	}

	/**
	 * This method is called from within the constructor to initialize the form.
	 * WARNING: Do NOT modify this code. The content of this method is always
	 * regenerated by the Form Editor.
	 */
	@SuppressWarnings("unchecked")
	// <editor-fold defaultstate="collapsed" desc="Generated Code">
	private void initComponents() {

		jButton1 = new javax.swing.JButton();
		jLabel_File = new javax.swing.JLabel();
		jLabel_Size = new javax.swing.JLabel();
		jLabel_Algorithm = new javax.swing.JLabel();
		jComboBox_Size = new javax.swing.JComboBox<>();
		jComboBox_Algorithm = new javax.swing.JComboBox<>();
		jLabel_Password = new javax.swing.JLabel();
		jPasswordField_Password = new javax.swing.JPasswordField();
		jTextField_File = new javax.swing.JTextField();
		jButton_File = new javax.swing.JButton();
		jButton_GenerateKey = new javax.swing.JButton();
		jButton_Signature = new javax.swing.JButton();
		jButton_Cipher = new javax.swing.JButton();

		jButton1.setText("jButton1");

		setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

		jLabel_File.setText("File");

		jLabel_Size.setText("Size");

		jLabel_Algorithm.setText("Algorithm");

		jComboBox_Size.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] {}));
		jComboBox_Size.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jComboBox_SizeActionPerformed(evt);
			}
		});

		jComboBox_Algorithm.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] {}));
		jComboBox_Algorithm.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jComboBox_AlgorithmActionPerformed(evt);
			}
		});

		jLabel_Password.setText("Password");

		jButton_File.setText("bower");
		jButton_File.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jButton_FileActionPerformed(evt);
			}
		});

		jButton_GenerateKey.setText("Generate Key");
		jButton_GenerateKey.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jButton_GenerateKeyActionPerformed(evt);
			}
		});

		jButton_Signature.setText("Signature");
		jButton_Signature.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jButton_SignatureActionPerformed(evt);
			}
		});

		jButton_Cipher.setText("Cipher");
		jButton_Cipher.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jButton_CipherActionPerformed(evt);
			}
		});

		javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
		getContentPane().setLayout(layout);
		layout.setHorizontalGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(layout.createSequentialGroup().addGap(37, 37, 37)
						.addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addComponent(jLabel_Size, javax.swing.GroupLayout.PREFERRED_SIZE, 147,
										javax.swing.GroupLayout.PREFERRED_SIZE)
								.addComponent(jLabel_Algorithm, javax.swing.GroupLayout.PREFERRED_SIZE, 147,
										javax.swing.GroupLayout.PREFERRED_SIZE)
								.addComponent(jLabel_File, javax.swing.GroupLayout.PREFERRED_SIZE, 147,
										javax.swing.GroupLayout.PREFERRED_SIZE)
								.addComponent(
										jLabel_Password, javax.swing.GroupLayout.PREFERRED_SIZE, 147,
										javax.swing.GroupLayout.PREFERRED_SIZE))
						.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
						.addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addGroup(layout
								.createSequentialGroup()
								.addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
										.addGroup(layout.createSequentialGroup()
												.addComponent(jButton_GenerateKey,
														javax.swing.GroupLayout.PREFERRED_SIZE, 201,
														javax.swing.GroupLayout.PREFERRED_SIZE)
												.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED,
														javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
												.addComponent(jButton_Signature, javax.swing.GroupLayout.PREFERRED_SIZE,
														160, javax.swing.GroupLayout.PREFERRED_SIZE)
												.addGap(243, 243, 243))
										.addGroup(layout.createSequentialGroup()
												.addComponent(jTextField_File, javax.swing.GroupLayout.PREFERRED_SIZE,
														718, javax.swing.GroupLayout.PREFERRED_SIZE)
												.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 23,
														Short.MAX_VALUE)))
								.addComponent(
										jButton_File, javax.swing.GroupLayout.PREFERRED_SIZE, 124,
										javax.swing.GroupLayout.PREFERRED_SIZE)
								.addGap(39, 39, 39))
								.addGroup(layout.createSequentialGroup().addGroup(layout
										.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
										.addComponent(jButton_Cipher, javax.swing.GroupLayout.PREFERRED_SIZE, 146,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
												.addComponent(jComboBox_Size, javax.swing.GroupLayout.PREFERRED_SIZE,
														324, javax.swing.GroupLayout.PREFERRED_SIZE)
												.addComponent(jComboBox_Algorithm,
														javax.swing.GroupLayout.PREFERRED_SIZE, 324,
														javax.swing.GroupLayout.PREFERRED_SIZE)
												.addComponent(jPasswordField_Password,
														javax.swing.GroupLayout.PREFERRED_SIZE, 718,
														javax.swing.GroupLayout.PREFERRED_SIZE)))
										.addGap(0, 0, Short.MAX_VALUE)))));
		layout.setVerticalGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(layout.createSequentialGroup().addGap(0, 82, Short.MAX_VALUE)
						.addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
								.addComponent(jLabel_Algorithm, javax.swing.GroupLayout.PREFERRED_SIZE, 50,
										javax.swing.GroupLayout.PREFERRED_SIZE)
								.addComponent(jComboBox_Algorithm, javax.swing.GroupLayout.PREFERRED_SIZE, 50,
										javax.swing.GroupLayout.PREFERRED_SIZE))
						.addGap(32, 32, 32)
						.addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
								.addComponent(jLabel_Size, javax.swing.GroupLayout.PREFERRED_SIZE, 49,
										javax.swing.GroupLayout.PREFERRED_SIZE)
								.addComponent(jComboBox_Size, javax.swing.GroupLayout.PREFERRED_SIZE, 49,
										javax.swing.GroupLayout.PREFERRED_SIZE))
						.addGap(30, 30, 30)
						.addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
								.addComponent(jLabel_File, javax.swing.GroupLayout.PREFERRED_SIZE, 42,
										javax.swing.GroupLayout.PREFERRED_SIZE)
								.addComponent(jButton_File, javax.swing.GroupLayout.PREFERRED_SIZE, 50,
										javax.swing.GroupLayout.PREFERRED_SIZE)
								.addComponent(jTextField_File, javax.swing.GroupLayout.PREFERRED_SIZE, 50,
										javax.swing.GroupLayout.PREFERRED_SIZE))
						.addGap(26, 26, 26)
						.addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
								.addComponent(jLabel_Password, javax.swing.GroupLayout.PREFERRED_SIZE, 46,
										javax.swing.GroupLayout.PREFERRED_SIZE)
								.addComponent(jPasswordField_Password, javax.swing.GroupLayout.PREFERRED_SIZE, 46,
										javax.swing.GroupLayout.PREFERRED_SIZE))
						.addGap(85, 85, 85)
						.addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
								.addComponent(jButton_GenerateKey, javax.swing.GroupLayout.PREFERRED_SIZE, 51,
										javax.swing.GroupLayout.PREFERRED_SIZE)
								.addComponent(jButton_Signature, javax.swing.GroupLayout.PREFERRED_SIZE, 51,
										javax.swing.GroupLayout.PREFERRED_SIZE)
								.addComponent(jButton_Cipher, javax.swing.GroupLayout.PREFERRED_SIZE, 51,
										javax.swing.GroupLayout.PREFERRED_SIZE))
						.addGap(115, 115, 115)));

		pack();
	}// </editor-fold>

	private void jComboBox_SizeActionPerformed(java.awt.event.ActionEvent evt) {
		// TODO add your handling code here:
	}

	private void jButton_FileActionPerformed(java.awt.event.ActionEvent evt) {
		JFileChooser chooser = new JFileChooser();
		if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
			pathKeyStore = chooser.getSelectedFile().getAbsolutePath();
		}
		jTextField_File.setText(pathKeyStore);
	}

	private void jComboBox_AlgorithmActionPerformed(java.awt.event.ActionEvent evt) {
		int itemCount = jComboBox_Algorithm.getSelectedIndex();
//      System.out.println("itemCount:"+itemCount);
		String alg = jComboBox_Algorithm.getItemAt(itemCount);
//  	System.out.println("alg:"+alg);
		if (alg.equals("AES")) {
//  		jComboBox_Size = new JComboBox<String>();
			jComboBox_Size.removeAllItems();
			jComboBox_Size.addItem("128");
			jComboBox_Size.addItem("192");
			jComboBox_Size.addItem("256");
		} else if (alg.equals("DES")) {
			jComboBox_Size.removeAllItems();
			jComboBox_Size.addItem("64");
		} else if (alg.equals("Blowfish")) {
			jComboBox_Size.removeAllItems();
			jComboBox_Size.addItem("224");
			jComboBox_Size.addItem("448");
		} else if (alg.equals("DESEDE")) {
			jComboBox_Size.removeAllItems();
			jComboBox_Size.addItem("192");
//  		jComboBox_Size.addItem("448");
		} else if (alg.equals("RSA")) {
			jComboBox_Size.removeAllItems();
			jComboBox_Size.addItem("1024");
			jComboBox_Size.addItem("2048");
			jComboBox_Size.addItem("4096");
//  		jComboBox_Size.addItem("448");
		} else if (alg.contains("ECDSA")) {
			jComboBox_Size.removeAllItems();
			jComboBox_Size.addItem("128");
			jComboBox_Size.addItem("256");
//  		jComboBox_Size.addItem("448");
		} else if (alg.equals("DSA")) {
			jComboBox_Size.removeAllItems();
			jComboBox_Size.addItem("512");
			jComboBox_Size.addItem("1024");
//  		jComboBox_Size.addItem("4096");
//  		jComboBox_Size.addItem("448");
		}
	}

	private void jButton_GenerateKeyActionPerformed(java.awt.event.ActionEvent evt) {
		int itemAlgorithm = jComboBox_Algorithm.getSelectedIndex();
		algorithmName = jComboBox_Algorithm.getItemAt(itemAlgorithm).toString().trim();
		int itemSize = jComboBox_Size.getSelectedIndex();
		size = jComboBox_Size.getItemAt(itemSize).toString().trim();
		pathKeyStore = jTextField_File.getText().toString().trim();
		password = new String(jPasswordField_Password.getPassword()).toString().trim();
		if ("".equals(pathKeyStore) || "".equals(password)) {
			JOptionPane.showMessageDialog(this, "Thiếu dữ liệu đầu vào");
		} else {
			String userName = DangNhap.userName;
			if (DangNhap.userName == null) {
				userName = "keystore";
			}
//			System.out.println("userName:" + userName);
			if (userName2 == null) {
				userName2 = "11111";
			}
			userName = userName2 + "_" + algorithmName;
			for (Object object : listAlgorithmCryptoAll) {
				AlgorithmCrypto algorithmCrypto = (AlgorithmCrypto) object;
				if (algorithmCrypto.getAlgorithmName().equals(algorithmName)) {
					type = algorithmCrypto.getType();
				}
			}
			if (type.equalsIgnoreCase("SecretKey")) {
				SecretKey secretKey = SecretKeyAlgorithmUtils.genKey(Integer.parseInt(size), algorithmName);
				boolean check = KeyStoreUtils.setKeyStoreSecretKey(pathKeyStore, password, secretKey, userName);
				if (check) {
//					JOptionPane.showMessageDialog(this, "thành công");
//					CipherService service = new CipherService();
//					service.setVisible(true);
//					this.setVisible(false);
					JOptionPane.showMessageDialog(this, "Sinh Key thành công\n" + pathKeyStore);
				} else if (!check) {
					JOptionPane.showMessageDialog(this, "Xảy ra lỗi trong quá trình sinh Key");
				}
			} else if (type.equalsIgnoreCase("PublicKey")) {
//	    		String userName = DangNhap.userName;
//				System.out.println("algorithmName:"+algorithmName);System.exit(0);
				PrivateKey privateKey = PublicKeyAlgorithmUtils.genKey(algorithmName, Integer.parseInt(size));
				Certificate[] certificates = PublicKeyAlgorithmUtils.genCertificate(userName, password, userName);
//				System.out.println("certificates.length:"+certificates.length);
//				System.out.println(certificates[0]);
//	    		boolean check = KeyStoreUtils.setKeyStoreSecretKey(pathKeyStore, password, secretKey, DangNhap.userName);
				boolean check = KeyStoreUtils.setKeyStorePKI(pathKeyStore, password, privateKey, certificates,
						userName);
				if (check) {
//					JOptionPane.showMessageDialog(this, "thành công");
//					System.out.println("algorithmName:"+algorithmName);
					JOptionPane.showMessageDialog(this, "Sinh Key thành công\n" + pathKeyStore);
//					SignatureService service = new SignatureService();
//					service.setVisible(true);
//					this.setVisible(false);
				} else if (!check) {
					JOptionPane.showMessageDialog(this, "Xảy ra lỗi trong quá trình sinh Key");
				}
			}
		}

	}

	private void jButton_SignatureActionPerformed(java.awt.event.ActionEvent evt) {
		SignatureService signatureService = new SignatureService();
		signatureService.setVisible(true);
		signatureService.setUsername2(userName2);
		this.setVisible(false);
	}

	private void jButton_CipherActionPerformed(java.awt.event.ActionEvent evt) {
		CipherService cipherService = new CipherService();
		cipherService.setVisible(true);
		cipherService.setUsername2(userName2);
		this.setVisible(false);
	}

	/**
	 * @param args the command line arguments
	 */
	public static void main(String args[]) {
		/* Set the Nimbus look and feel */
		// <editor-fold defaultstate="collapsed" desc=" Look and feel setting code
		// (optional) ">
		/*
		 * If Nimbus (introduced in Java SE 6) is not available, stay with the default
		 * look and feel. For details see
		 * http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html
		 */
		try {
			for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
				if ("Nimbus".equals(info.getName())) {
					javax.swing.UIManager.setLookAndFeel(info.getClassName());
					break;
				}
			}
		} catch (ClassNotFoundException ex) {
			java.util.logging.Logger.getLogger(GenerateKey.class.getName()).log(java.util.logging.Level.SEVERE, null,
					ex);
		} catch (InstantiationException ex) {
			java.util.logging.Logger.getLogger(GenerateKey.class.getName()).log(java.util.logging.Level.SEVERE, null,
					ex);
		} catch (IllegalAccessException ex) {
			java.util.logging.Logger.getLogger(GenerateKey.class.getName()).log(java.util.logging.Level.SEVERE, null,
					ex);
		} catch (javax.swing.UnsupportedLookAndFeelException ex) {
			java.util.logging.Logger.getLogger(GenerateKey.class.getName()).log(java.util.logging.Level.SEVERE, null,
					ex);
		}
		// </editor-fold>

		/* Create and display the form */
		java.awt.EventQueue.invokeLater(new Runnable() {
			public void run() {
				new GenerateKey().setVisible(true);
			}
		});
	}

	// Variables declaration - do not modify
	private javax.swing.JButton jButton1;
	private javax.swing.JButton jButton_Cipher;
	private javax.swing.JButton jButton_File;
	private javax.swing.JButton jButton_GenerateKey;
	private javax.swing.JButton jButton_Signature;
	private javax.swing.JComboBox<String> jComboBox_Algorithm;
	private javax.swing.JComboBox<String> jComboBox_Size;
	private javax.swing.JLabel jLabel_Algorithm;
	private javax.swing.JLabel jLabel_File;
	private javax.swing.JLabel jLabel_Password;
	private javax.swing.JLabel jLabel_Size;
	private javax.swing.JTextField jTextField_File;
	private javax.swing.JPasswordField jPasswordField_Password;
	// End of variables declaration
}
