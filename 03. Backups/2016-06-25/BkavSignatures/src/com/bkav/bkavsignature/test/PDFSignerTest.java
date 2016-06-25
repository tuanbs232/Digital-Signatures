package com.bkav.bkavsignature.test;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.bkav.bkavsignature.pdf.PDFSigner;
import com.bkav.bkavsignature.utils.BkavSignaturesException;
import com.bkav.bkavsignature.utils.CryptoToken;
import com.bkav.bkavsignature.utils.CryptoTokenUtil;
import com.bkav.bkavsignature.utils.FileUtil;

public class PDFSignerTest {
	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());
		String input = "S:/WORK/2016/05-2016/Test_files/input.pdf";
		String output = "C:/Users/TUANBS/Desktop/signed.pdf";
		String keystorePath = "S:/WORK/2016/03-2016/PKCS12_TOKEN/test_Ng2v2m0dJcQXhdav9FqF.p12";
		String keystorePass = "123456";
		try {
			FileInputStream inStream = new FileInputStream(keystorePath);
			CryptoToken token = null;
			try {
				token = CryptoTokenUtil.initFromPkcs12(inStream, keystorePass);
			} catch (BkavSignaturesException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			sign(input, output, token);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
	}
	public static void sign(String input, String output, CryptoToken token){
		byte[] data;
		try {
			data = FileUtil.readBytesFromFile(input);
			byte[] signed = PDFSigner.sign(data, token);
			FileUtil.writeToFile(signed, output);
		} catch (IOException e) {
			e.printStackTrace();
		} catch (BkavSignaturesException e) {
			e.printStackTrace();
		}
	}
}
