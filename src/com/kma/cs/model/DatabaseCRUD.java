package com.kma.cs.model;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

public class DatabaseCRUD {

	private static final String hostName = "localhost";
	private static final String dbName = "cryptoservice";
	private static final String userName = "root";
	private static final String password = "123456";
	private static final String connectionURL = "jdbc:mysql://" + hostName + ":3306/" + dbName;
	private static final Connection conn;
//    private static 

	static {
		conn = openConnection();
	}

	public static Connection openConnection() {
		Connection conn = null;
		try {
			DriverManager.registerDriver(new com.mysql.cj.jdbc.Driver());
			conn = DriverManager.getConnection(connectionURL, userName, password);
			return conn;
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return conn;
	}

//	public static Connection openConnection() {
//		Connection conn = null;
//		try {
//			DriverManager.registerDriver(new com.mysql.cj.jdbc.Driver());
//			conn = DriverManager.getConnection(connectionURL, userName, password);
//			return conn;
//		} catch (SQLException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//		return conn;
//	}

	// create
	public static boolean createTable(String sql, String... args) {
		PreparedStatement pstm = null;
		try {
			pstm = conn.prepareStatement(sql);
			System.out.println("sql:"+sql);
			if (args != null && args.length > 0) {
				String[] input = args.clone();
				for (int i = 0; i < input.length; i++) {
					pstm.setString(i + 1, input[i]);
				}
			}
			pstm.executeUpdate();
			return true;
		} catch (SQLException e) {
			e.printStackTrace();
		}
		return false;
	}

	// read
	public static List getTable(String sql, String type) {
		Statement st = null;
		List list = new ArrayList();
		try {
			st = conn.createStatement(ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY);
			ResultSet rs = st.executeQuery(sql);
			while (rs.next()) {
				if (type.equalsIgnoreCase("user")) {
					User user = new User();
					user.setMail(rs.getString("mail"));
					user.setPassword(rs.getString("password"));
					user.setUserId(rs.getString("userId"));
					user.setUserName(rs.getString("userName"));
					list.add(user);
//					return user;
				} else if (type.equalsIgnoreCase("cryptoToken")) {
					CryptoToken cryptoToken = new CryptoToken();
					cryptoToken.setPassKey(rs.getString("passKey"));
					cryptoToken.setPathKey(rs.getString("pathKey"));
					cryptoToken.setTokenId(rs.getString("tokenId"));
					cryptoToken.setUserId(rs.getString("userId"));
//					return cryptoToken;
					list.add(cryptoToken);
				} else if (type.equalsIgnoreCase("algorithmCrypto")) {
					AlgorithmCrypto algorithmCrypto = new AlgorithmCrypto();
					algorithmCrypto.setAlgorithmId(rs.getString("algorithmId"));
					algorithmCrypto.setAlgorithmName(rs.getString("algorithmName"));
					algorithmCrypto.setType(rs.getString("type"));
//					return algorithmCrypto;
					list.add(algorithmCrypto);
				}
			}
			return list;
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	// update
	public static boolean updateTable(String sqlUpdate, String... args) {
		PreparedStatement pstmt = null;
		try {
			pstmt = conn.prepareStatement(sqlUpdate);
			if (args != null && args.length > 0) {
				String[] input = args.clone();
				for (int i = 0; i < input.length; i++) {
					pstmt.setString(i + 1, input[i]);
				}
			}
			pstmt.executeUpdate();
			return true;
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
	}

	// delete
	public static boolean deleteData(String sqlDelete, String... args) {
		PreparedStatement pstmt = null;
		try {
			pstmt = conn.prepareStatement(sqlDelete);
			if (args != null && args.length > 0) {
				String[] input = args.clone();
				for (int i = 0; i < input.length; i++) {
					pstmt.setString(i + 1, input[i]);
				}
			}
			pstmt.executeUpdate();
			return true;
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
	}
}
