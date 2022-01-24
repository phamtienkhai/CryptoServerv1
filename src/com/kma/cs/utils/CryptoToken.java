package com.kma.cs.utils;

import java.security.PrivateKey;
import java.security.cert.Certificate;

public class CryptoToken {
	private PrivateKey privateKey;
	private Certificate cert;
	private Certificate[] certChain;

	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	public Certificate getCert() {
		return cert;
	}

	public Certificate[] getCertChain() {
		return certChain;
	}

	public CryptoToken(PrivateKey privateKey, Certificate cert, Certificate[] certChain) {
		super();
		this.privateKey = privateKey;
		this.cert = cert;
		this.certChain = certChain;
	}
}
