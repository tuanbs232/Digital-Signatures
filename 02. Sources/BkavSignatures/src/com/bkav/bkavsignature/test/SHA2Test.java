package com.bkav.bkavsignature.test;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import com.bkav.bkavsignature.utils.BkavSignaturesException;
import com.bkav.bkavsignature.utils.CryptoToken;
import com.bkav.bkavsignature.utils.CryptoTokenUtil;

public class SHA2Test {
	public static void main(String[] args) {
		checkPrivatekey();
	}
	public static void checkPrivatekey() {
		String keystorePath = "S:/WORK/2016/07-2016/SHA2/SHA2/Cert_sha2.p12";
		String keystorePass = "1";

		File file = new java.io.File(keystorePath);
		try {
			FileInputStream inStream = new FileInputStream(file);
			CryptoToken token = CryptoTokenUtil.initFromPkcs12(inStream,
					keystorePass);
			if(token != null){
				PrivateKey privateKey = token.getPrivateKey();
				if(privateKey != null){
					System.out.println(privateKey.getAlgorithm());
				}
				X509Certificate cert = token.getSignerCert();
				System.out.println(cert);
			}
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BkavSignaturesException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
