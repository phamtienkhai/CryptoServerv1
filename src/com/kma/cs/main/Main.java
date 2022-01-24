package com.kma.cs.main;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Provider.Service;
import java.security.Security;
import java.util.Set;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.kma.cs.model.CryptoToken;
import com.kma.cs.model.User;
import com.kma.cs.utils.CryptoTokenUtils;
import com.kma.cs.utils.UserUtils;

public class Main {
	public static void main(String[] args) {
//		System.out.println("Hello world!");
//		addProviders();
//		genKey();
//		boolean checkUser = M
//		User user = new User("122322", "1223222", "khaihackerqsc@gmail.com", 1222222222);
//		UserUtils.createUser(user);
//		CryptoToken cryptoToken = new CryptoToken(1222222222, 1222222, "11111111", "1111111111");
//		CryptoTokenUtils.createToken(cryptoToken);
//		Security.addProvider(new BouncyCastleProvider());
//		Provider provider = Security.getProvider("BC");
//		Set<Service> services = provider.getServices();//services.
////		Iterator<String> iterator = ser.iterator();
////		while(iterator.hasNext(){
////		  String element = iterator.next();
////		}
////		services.i
//		for(Service service : services) {
//			String alg = service.getAlgorithm();
//			String type = service.getClassName();
////			if(alg.contains("AES")) {
////				System.out.println(type);
////			}
//			System.out.println("alg:"+alg);
//			System.out.println("type:"+type);
//		}
//		String file = "D:\akdjflk\kdjfjl.xml";
	}
	
	public static void addProviders() {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	private static void genKey() {
		try {
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
			kpg.initialize(2048);
			KeyPair kp = kpg.generateKeyPair();
			System.out.println(kp.getPrivate().getAlgorithm());
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
