package com.bkav.bkavsignature.test;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.bkav.bkavsignature.utils.CryptoToken;
import com.bkav.bkavsignature.utils.CryptoTokenUtil;
import com.bkav.bkavsignature.validationservice.CertificateValidator;
import com.bkav.bkavsignature.validationservice.OCSPValidator;

public class CertificateRevocationTest {
	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());
		testCertRevoked() ;
	}

	public static void crossCertificateTest1() {
		String certPath = "S:/WORK/2016/01-2016/ClientCA1.cer";
		try {
			CertificateFactory factory = CertificateFactory.getInstance("X509");
			X509Certificate clientCert = (X509Certificate) factory
					.generateCertificate(
							new FileInputStream(new File(certPath)));

			Date signingTime = createDate(2016, 01, 10);
			int code = CertificateValidator.verify(clientCert, null, signingTime);
			System.out.println(code);
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
	}

	public static void crossCertificateTest() {
		String certPath = "S:/WORK/2016/01-2016/ClientCA1.cer";
		String ca2Path = "C:/BkavCA/Certificates/CA2.cer";
		try {
			CertificateFactory factory = CertificateFactory.getInstance("X509");
			X509Certificate clientCert = (X509Certificate) factory
					.generateCertificate(
							new FileInputStream(new File(certPath)));

			X509Certificate ca2 = (X509Certificate) factory.generateCertificate(
					new FileInputStream(new File(ca2Path)));

			Date signingTime = new Date();

			int code = OCSPValidator.getRevocationStatus(clientCert, ca2,
					signingTime);
			System.out.println(code);
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
	}

	public static void testBkavOldAndNew() {
		String certOldPath = "S:/WORK/2015/12-2015/BkavCA.cer";
		String certNewPath = "S:/WORK/2015/12-2015/BkavCA_new.cer";
		try {
			CertificateFactory factory = CertificateFactory.getInstance("X509");
			X509Certificate certOld = (X509Certificate) factory
					.generateCertificate(
							new FileInputStream(new File(certOldPath)));

			X509Certificate certNew = (X509Certificate) factory
					.generateCertificate(
							new FileInputStream(new File(certNewPath)));
			RSAPublicKey pubOld = (RSAPublicKey) certOld.getPublicKey();
			System.out.println("OLD: " + pubOld.getModulus());
			RSAPublicKey pubNew = (RSAPublicKey) certNew.getPublicKey();
			System.out.println("NEW: " + pubNew.getModulus());
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
	}

	public static void testCertOK() {
		String serial = "5403530ff2f88cf3cde9c5d6edb47321";
		CryptoToken token = CryptoTokenUtil.initFromTokenCSP(serial);

		// Not before: 2015/04/16 Not after: 2015/07/14 Revoked: 2015/05/27
		// 16:38:05
		X509Certificate signerCert = token.getCertificate();
		Certificate[] certChain = token.getCertChain();
		System.out.println(signerCert.getNotBefore());
		System.out.println(signerCert.getNotAfter());

		Date signingTime = createDate(2015, 8, 18);

		CertificateValidator.verify(signerCert, certChain, signingTime,
				CertificateValidator.ONLY_CRL);
	}

	public static void testCertRevoked() {
		String keystorePath = "E:\\Company\\BKAV\\Code_Demo\\540346B323887B4E02744AC4EC6D4460_Revoked_d3jpWqicAsRZ.p12";
		String keystorePass = "d3jpWqicAsRZ";
		// String keystorePath = "S:/WORK/2015/12-2015/BCSE_Client.p12";
		// String keystorePass = "12345678";
		CryptoToken token = CryptoTokenUtil.initFromPKCS12(keystorePath,
				keystorePass);

		// Not before: 2015/04/16 Not after: 2015/07/14 Revoked: 2015/05/27
		// 16:38:05
		X509Certificate signerCert = token.getCertificate();
		Certificate[] certChain = token.getCertChain();
		System.out.println(signerCert.getNotBefore());
		System.out.println(signerCert.getNotAfter());

		Date signingTime = createDate(2015, 6, 24);

		int code = CertificateValidator.verify(signerCert, certChain,
				signingTime, CertificateValidator.ONLY_OCSP);
		System.out.println("RESULT: " + code);
	}

	private static Date createDate(int year, int month, int day) {
		String source = year + "/" + month + "/" + day;
		SimpleDateFormat df = new SimpleDateFormat("yyyy/MM/dd");
		try {
			return df.parse(source);
		} catch (ParseException e) {
			return new Date();
		}
	}

}
