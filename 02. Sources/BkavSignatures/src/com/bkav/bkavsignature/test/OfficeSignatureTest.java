package com.bkav.bkavsignature.test;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

import com.bkav.bkavsignature.ooxml.OOXMLSigner;
import com.bkav.bkavsignature.ooxml.OOXMLValidator;
import com.bkav.bkavsignature.utils.BkavSignaturesException;
import com.bkav.bkavsignature.utils.CryptoToken;
import com.bkav.bkavsignature.utils.CryptoTokenUtil;
import com.bkav.bkavsignature.utils.FileUtil;
import com.bkav.bkavsignature.validationservice.CertificateValidator;

public class OfficeSignatureTest {
	public static void main(String[] args) {
		verifyOffice();
	}
	public static void signOffice(){
		String testData = "S:/WORK/2016/05-2016/Test_files/input.docx";
		String outPath = "S:/WORK/2016/05-2016/Test_files/Signeds/signed.docx";
		
		String keystorePath = "S:/WORK/2016/03-2016/PKCS12_TOKEN/BCSE_Client.p12";
		String keystorePass = "12345678";
		try {
			byte[] data = FileUtil.readBytesFromFile(testData);
			InputStream inStream = new FileInputStream(keystorePath);
			CryptoToken token = CryptoTokenUtil.initFromPkcs12(inStream, keystorePass);
			byte[] signedBytes = OOXMLSigner.sign(data, token);
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
	
	public static void verifyOffice(){
		String signedPath = "C:/Users/AD/Desktop/signed.docx";
		try {
			byte[] input = FileUtil.readBytesFromFile(signedPath);
			int result = OOXMLValidator.verify(input, CertificateValidator.ONLY_CRL);
			System.out.println(result);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
