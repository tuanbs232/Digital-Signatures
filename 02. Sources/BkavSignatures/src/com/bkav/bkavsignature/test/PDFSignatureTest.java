package com.bkav.bkavsignature.test;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

import com.bkav.bkavsignature.pdf.PDFSigner;
import com.bkav.bkavsignature.utils.BkavSignaturesException;
import com.bkav.bkavsignature.utils.CryptoToken;
import com.bkav.bkavsignature.utils.CryptoTokenUtil;
import com.bkav.bkavsignature.utils.FileUtil;

public class PDFSignatureTest {
	public static void main(String[] args) {
		signPDFTest();
	}

	public static void signPDFTest(){
		String testData = "S:/WORK/2016/05-2016/Test_files/input.pdf";
		String outPath = "S:/WORK/2016/05-2016/Test_files/Signeds/signed.pdf";
		String keystorePath = "S:/WORK/2016/03-2016/PKCS12_TOKEN/BCSE_Client.p12";
		String keystorePass = "12345678";
		try {
			byte[] data = FileUtil.readBytesFromFile(testData);
			InputStream inStream = new FileInputStream(keystorePath);
			CryptoToken token = CryptoTokenUtil.initFromPkcs12(inStream, keystorePass);
			byte[] signedBytes = PDFSigner.sign(data, token, "XXX", "XXX");
			if(signedBytes != null){
				FileUtil.writeToFile(signedBytes, outPath);
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BkavSignaturesException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public static void signWithEToken(){
		String configDir = "S:/WORK/2016/06-2016/E-Token/config.cfg";
		String pin = "12345678";
		
		CryptoToken token = null;
		try {
			token = CryptoTokenUtil.initFromPkcs11(configDir, pin);
		} catch (BkavSignaturesException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		if(token == null){
			System.out.println("Token null");
			return;
		}
		
		String testData = "S:/WORK/2016/05-2016/Test_files/input.pdf";
		try {
			byte[] data = FileUtil.readBytesFromFile(testData);
			byte[] signedBytes = PDFSigner.sign(data, token);
			if(signedBytes != null){
				System.out.println("signed");
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BkavSignaturesException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
