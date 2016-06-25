package com.bkav.bkavsignature.test;

import java.io.IOException;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.bkav.bkavsignature.pdf.PDFValidator;
import com.bkav.bkavsignature.utils.FileUtil;
import com.bkav.bkavsignature.validationservice.CertificateValidator;

public class PDFValidatorTest {

	public static void main(String[] args) {
		String signedDoc = "C:/Users/TUANBS/Desktop/signed.pdf";
		verify(signedDoc);
	}

	public static void verify(String signedDoc) {
		Security.addProvider(new BouncyCastleProvider());
		byte[] signedData;
		try {
			signedData = FileUtil.readBytesFromFile(signedDoc);
			System.out.println("---> Result code: " + PDFValidator
					.verify(signedData, CertificateValidator.ONLY_OCSP));
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
