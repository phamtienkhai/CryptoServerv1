package com.kma.cs.model;

public class CryptoToken {
	private String userId;
	private String tokenId;
	private String pathKey;
	private String passKey;
	
	public CryptoToken() {};

	public CryptoToken(String userId, String tokenId, String pathKey, String passKey) {
		super();
		this.userId = userId;
		this.tokenId = tokenId;
		this.pathKey = pathKey;
		this.passKey = passKey;
	}

	public String getUserId() {
		return userId;
	}

	public String getTokenId() {
		return tokenId;
	}

	public String getPathKey() {
		return pathKey;
	}

	public String getPassKey() {
		return passKey;
	}

	public void setUserId(String userId) {
		this.userId = userId;
	}

	public void setTokenId(String tokenId) {
		this.tokenId = tokenId;
	}

	public void setPathKey(String pathKey) {
		this.pathKey = pathKey;
	}

	public void setPassKey(String passKey) {
		this.passKey = passKey;
	}

}
