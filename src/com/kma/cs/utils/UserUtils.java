package com.kma.cs.utils;

import java.util.List;

import com.kma.cs.model.*;
import com.kma.cs.utils.mail.SendMail;
import com.kma.cs.utils.otp.OTPService;

public class UserUtils {

	static MysqlUtils mysqlUtils;
//	static String fromMail = "";
//	String String passFromMail = "";

	static {
		mysqlUtils = new MysqlUtils();
	}

	public static boolean createUser(User user) {
		String userName = "";
		String password = "";
		String mail = ""; 
		String userId = "-1";
		if(user != null) {
			userName = user.getUserName();
			password = user.getPassword();
			mail = user.getMail();
//			userId = user.getUserId();
			userId = "";
		} else
			return false;
		
		String sqlStr = "INSERT INTO User values(?,?,?,?);";
		try {
			if(!mysqlUtils.checkUser(userName, password)) {
				boolean check = mysqlUtils.insertIntoData(sqlStr, "User", userName, password, mail, userId + "");
				OTPService service = new OTPService();
				String otp = service.generatorCode();
				SendMail sendMail = new SendMail();
				String fromMail = "chusau7mau@gmail.com";
				String passwordFromMail = "chusau7maua@A123z!";
				sendMail.send(fromMail, passwordFromMail, mail, otp);
				return check;
			}		
//			return false;
		} catch (Exception e) {
			return false;
		}
		return false;
	}
	
	public static List<User> getUser(){
		return mysqlUtils.listUser;
	}
}
