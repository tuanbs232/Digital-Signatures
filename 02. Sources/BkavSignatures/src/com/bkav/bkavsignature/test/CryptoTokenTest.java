package com.bkav.bkavsignature.test;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;

import com.bkav.bkavsignature.utils.BkavSignaturesException;
import com.bkav.bkavsignature.utils.CryptoToken;
import com.bkav.bkavsignature.utils.CryptoTokenUtil;

public class CryptoTokenTest {
	public static void main(String[] args) {
		inFromPkcs12InvalidType();
	}
	
	public static void initFromPkcs12(){
		String keystorePath = "S:/WORK/2016/03-2016/PKCS12_TOKEN/BCSE_Client.p12";
		CryptoToken token = null;
		try {
			InputStream inStream = new FileInputStream(keystorePath);
			token = CryptoTokenUtil.initFromPkcs12(inStream, "");
		} catch (BkavSignaturesException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println(token == null);
	}
	
	public static void inFromPkcs12InvalidType(){
		String keystorePath = "S:/WORK/PROJECTS/Bkav_Token_config/config.cfg";
		CryptoToken token = null;
		try {
			InputStream inStream = new FileInputStream(keystorePath);
			token = CryptoTokenUtil.initFromPkcs12(inStream, "");
		} catch (BkavSignaturesException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println(token == null);
	}
	public static void initFromPkcs11test(){
		String configDir = "S:/WORK/PROJECTS/Bkav_Token_config/config.cfg";
		String pin = "78808995";
		
		CryptoToken token;
		try {
			token = CryptoTokenUtil.initFromPkcs11(configDir, pin);
			if(token == null){
				System.out.println("Token null");
				return;
			}
			System.out.println(token.getPrivateKey());
		} catch (BkavSignaturesException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		CryptoToken token1;
		try {
			token1 = CryptoTokenUtil.initFromPkcs11(configDir, pin);
			if(token1 == null){
				System.out.println("Token null");
				return;
			}
			System.out.println(token1.getPrivateKey());
		} catch (BkavSignaturesException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public static void initFromeToken(){
		String configDir = "S:/WORK/2016/06-2016/E-Token/config.cfg";
		String pin = "12345678";
		
		CryptoToken token;
		try {
			token = CryptoTokenUtil.initFromPkcs11(configDir, pin);
			if(token == null){
				System.out.println("Token null");
				return;
			}
			System.out.println(token.getCertChain().length);
		} catch (BkavSignaturesException e) {
			System.out.println(e.getMessage());
		}
		
		CryptoToken token1;
		try {
			token1 = CryptoTokenUtil.initFromPkcs11(configDir, pin);
			if(token1 == null){
				System.out.println("Token null");
				return;
			}
			System.out.println(token1.getPrivateKey());
		} catch (BkavSignaturesException e) {
			System.out.println(e.getMessage());
		}
	}
}
