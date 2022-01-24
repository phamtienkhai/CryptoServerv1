package com.kma.cs.utils;

import java.sql.Connection;
import java.util.List;

import com.kma.cs.model.CryptoToken;
import com.kma.cs.model.User;

public class CryptoTokenUtils {
	static MysqlUtils mysqlUtils;

	static {
		mysqlUtils = new MysqlUtils();
	}

	public static boolean createToken(CryptoToken cryptoToken) {
		String userId = "-1";
		String tokenId = "-1";
		String pathKey = "";
		String passKey = "";
		if(cryptoToken != null) {
			userId = cryptoToken.getUserId();
			tokenId = cryptoToken.getTokenId();
			pathKey = cryptoToken.getPathKey();
			passKey = cryptoToken.getPassKey();
		} else
			return false;
		String sqlStr = "INSERT INTO CryptoToken values(?,?,?,?);";
		try {
			boolean check = mysqlUtils.insertIntoData(sqlStr, "CryptoToken", userId + "", tokenId + "", pathKey, passKey);
			return check;
		} catch (Exception e) {
			return false;
		}
	}
	
	public static List getCryptoToken() {
		Connection connection = mysqlUtils.connection;
		return mysqlUtils.selectData(connection, "SELECT * FROM CryptoToken;");
	}

}
