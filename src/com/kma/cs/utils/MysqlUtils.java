package com.kma.cs.utils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import com.kma.cs.model.User;

public class MysqlUtils {
	static String url = "jdbc:mysql://localhost:3306/cryptoservice";
	static String user = "root";
	static String password = "123456";
	public static Connection connection;
	static boolean checkConnect = getConnection();
	public static List listUser;

	public static boolean getConnection() {
		Connection conn = null;
		try {
			Class.forName("com.mysql.cj.jdbc.Driver");
			conn = DriverManager.getConnection(url, user, password);
			connection = conn;
			selectData(conn, "SELECT * FROM User;");
			System.out.println("connect successfully!");
			return false;
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
			return true;
		} catch (SQLException e) {
			e.printStackTrace();
			return true;
		}
	}

	public static List selectData(Connection conn, String sql) {
		PreparedStatement pstm;
		List listUser2 = new ArrayList();
		try {
			pstm = conn.prepareStatement(sql);
			ResultSet rs = pstm.executeQuery();
			if(sql.contains("User")) {
				while (rs.next()) {
					String userName, password, mail;
					String userId;
					userName = rs.getString(1);
					password = rs.getString(2);
					mail = rs.getString(3);
//					userId = rs.getInt(4);
					userId = "";
					listUser2.add(new User(userName, password, mail, userId));
				}
				listUser = listUser2;
			} else if(sql.contains("CryptoToken")) {
				while (rs.next()) {
					String pathKey, passKey;
					String userId, tokenId;
//					userId = rs.getInt(1);
//					tokenId= rs.getInt(2);
					userId = "";
					tokenId= "";
					pathKey = rs.getString(3);
//					passKey = rs.getString(4);
					passKey = "";
					listUser2.add(new com.kma.cs.model.CryptoToken(userId, tokenId, pathKey, passKey));
				}
			}
			
		} catch (SQLException e) {
			e.printStackTrace();
		}		
		return listUser2;
	}

	public static boolean checkUser(String userName, String password) {
		password = encodeMD(password.getBytes());
		for (Object object : listUser) {
			User user = (User) object;
			if (user.getUserName().equals(userName) && user.getPassword().equals(password))
				return true;
		}
		return false;
	}

	public static boolean insertIntoData(String sql, String nameTable, String... args) {
		PreparedStatement pstm;
//		System.out.println("nameTable:"+nameTable);System.exit(0);
		try {
			pstm = connection.prepareStatement(sql);
			if (args != null && args.length > 0) {
				String[] input = args.clone();
				for (int i = 0; i < input.length; i++) {
					String password = "";
					if (i == 1 && nameTable.equals("User")) {
						password = encodeMD(input[i].getBytes());
						pstm.setString(i + 1, password);
						continue;
					}
					
					if (i == 3 && nameTable.equals("User")) {
//						System.out.println("ccccccc");System.exit(0);
//						password = encodeMD(input[i].getBytes());
						pstm.setInt(i + 1, Integer.parseInt(input[i]));
						continue;
					}

					else if ((i == 0 || i == 2) && nameTable.equals("CryptoToken")) {
						pstm.setInt(i + 1, Integer.parseInt(input[i]));
						continue;
					}

					else if ((i == 2) && (nameTable.equals("AlgorithmCrypto"))) {
						pstm.setInt(i + 1, Integer.parseInt(input[i]));
						continue;
					}

					pstm.setString(i + 1, input[i]);
				}
			}
			pstm.executeUpdate();
			selectData(connection, "SELECT * FROM User");
			return false;
		} catch (SQLException e) {
			e.printStackTrace();
		}
		return true;
	}

	private static String encodeMD(byte[] data) {
		String algmd = "sha1";
		try {
			MessageDigest md = MessageDigest.getInstance(algmd);
			md.update(data);
			byte[] dataMD = md.digest();
			return java.util.Base64.getEncoder().encodeToString(dataMD);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	public static void main(String[] args) {
		encodeMD("aaa".getBytes());
	}
}
