package com.bkav.bkavsignature.test;

import java.io.IOException;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.bkav.bkavsignature.pdf.PDFSigner;
import com.bkav.bkavsignature.utils.CryptoToken;
import com.bkav.bkavsignature.utils.CryptoTokenUtil;
import com.bkav.bkavsignature.utils.FileUtil;

public class PDFSignerTest {
	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());
		String input = "S:/WORK/2016/01-2016/input.pdf";
		String output = "C:/Users/BuiSi/Desktop/signed.pdf";
		String keystorePath = "S:/WORK/2015/12-2015/540346B323887B4E02744AC4EC6D4460_Revoked_d3jpWqicAsRZ.p12";
		String keystorePass = "d3jpWqicAsRZ";
		CryptoToken token = CryptoTokenUtil.initFromPKCS12(keystorePath, keystorePass);
		
		sign(input, output, token);
	}
	public static void sign(String input, String output, CryptoToken token){
		byte[] data;
		try {
			data = FileUtil.readBytesFromFile(input);
			byte[] signed = PDFSigner.sign(data, token);
			FileUtil.writeToFile(signed, output);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
