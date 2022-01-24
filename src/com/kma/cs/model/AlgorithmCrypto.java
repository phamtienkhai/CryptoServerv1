package com.kma.cs.model;

public class AlgorithmCrypto {
	private String algorithmName;
	private String algorithmId;
	private String type;
	
	public AlgorithmCrypto() {};

	public AlgorithmCrypto(String algorithmName, String algorithmId, String type) {
		super();
		this.algorithmName = algorithmName;
		this.algorithmId = algorithmId;
		this.type = type;
	}

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}

	public String getAlgorithmName() {
		return algorithmName;
	}

	public void setAlgorithmName(String algorithmName) {
		this.algorithmName = algorithmName;
	}

	public String getAlgorithmId() {
		return algorithmId;
	}

	public void setAlgorithmId(String algorithmId) {
		this.algorithmId = algorithmId;
	}

}
