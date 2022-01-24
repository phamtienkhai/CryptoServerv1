package com.kma.cs.model;

public class User {
	private String userName;
	private String password;
	private String mail;
	private String userId;
	
	public User() {};

	public User(String userName, String password, String mail, String userId) {
		super();
		this.userName = userName;
		this.password = password;
		this.mail = mail;
		this.userId = userId;
	}

	public String getUserName() {
		return userName;
	}

	public String getPassword() {
		return password;
	}

	public String getMail() {
		return mail;
	}

	public String getUserId() {
		return userId;
	}

	public void setUserName(String userName) {
		this.userName = userName;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public void setMail(String mail) {
		this.mail = mail;
	}

	public void setUserId(String userId) {
		this.userId = userId;
	}

}
