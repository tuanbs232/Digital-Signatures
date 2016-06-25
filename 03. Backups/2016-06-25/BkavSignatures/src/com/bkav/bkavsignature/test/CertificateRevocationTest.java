package com.bkav.bkavsignature.test;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.log4j.Logger;

import com.bkav.bkavsignature.utils.BkavSignaturesException;
import com.bkav.bkavsignature.utils.CryptoToken;
import com.bkav.bkavsignature.utils.CryptoTokenUtil;
import com.bkav.bkavsignature.validationservice.CertificateValidator;
import com.bkav.bkavsignature.validationservice.OCSPValidator;
import com.itextpdf.text.pdf.codec.Base64;

public class CertificateRevocationTest {
	private static final Logger LOG = Logger
			.getLogger(CertificateRevocationTest.class);

	static String SUB_RA_CERT_1 = "MIIEHDCCAwSgAwIBAgIQVAMv2cWFTP8PWmh0TMCYxTANBgkqhkiG9w0BAQUFADBJMQswCQYDVQQGEwJWTjEOMAwGA1UEBxMFSGFub2kxGTAXBgNVBAoTEEJrYXYgQ29ycG9yYXRpb24xDzANBgNVBAMTBkJrYXZDQTAeFw0xNTA2MjMxNDIzMjBaFw0xNjA2MjIxNDIzMjBaMIGTMR4wHAYKCZImiZPyLGQBAQwOTVNUOjAyMDEyOTUxMDYxOjA4BgNVBAMMMUPDtG5nIFR5IFROSEggxJDhuqd1IFTGsCBE4buLY2ggVuG7pSBIb8OgbmcgUGjDoXQxETAPBgNVBAcMCEjhuqNpIEFuMRUwEwYDVQQIDAxI4bqjaSBQaMOybmcxCzAJBgNVBAYTAlZOMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCMkCd4cDDHKgUoGlp3CXWwbL6Vceid8l4QVh4sohsvUpAMbpHXheIP+YqmLZCcndrnSV4FPo36kxtDLwNt+zIgtbPmYw2WYvuf57CfVNH4ObLX0kIG9cdMQwHhoFYmCswQ7hs/s/lk8PriQqXl+6bor4mce7uduKpxp3PWXnuXyQIDAQABo4IBNzCCATMwMQYIKwYBBQUHAQEEJTAjMCEGCCsGAQUFBzABhhVodHRwOi8vb2NzcC5ia2F2Y2Eudm4wHQYDVR0OBBYEFNizSU2eCIhn0J0sJ3mJnY8b8E+WMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUHrAPSJff0MNnp0aEO1g7iA1TlIYwfwYDVR0fBHgwdjB0oCOgIYYfaHR0cDovL2NybC5ia2F2Y2Eudm4vQmthdkNBLmNybKJNpEswSTEPMA0GA1UEAwwGQmthdkNBMRkwFwYDVQQKDBBCa2F2IENvcnBvcmF0aW9uMQ4wDAYDVQQHDAVIYW5vaTELMAkGA1UEBhMCVk4wDgYDVR0PAQH/BAQDAgeAMB8GA1UdJQQYMBYGCCsGAQUFBwMEBgorBgEEAYI3CgMMMA0GCSqGSIb3DQEBBQUAA4IBAQCPqZU1E3MRNU+jldlfbsUs3ImrTWh4lQSlnax5ytIyLHmShl6LABpkLyFO+yETSlYh6wAei+ERACEd118msatnkxJEfMSrh4QEhQvD/d9WyOVpMIz+Kc+wxgwUP26ow64ot24EUKNg63q9dTVCPRPlUV/nZC1avxCky7BJNaonbBGIpugxkhla0e7YAvIQsOfbo3moUlvltmUAdAuwDVfrzd2DQqpQsg0peJMy2bEQhu3twosl/0T4pukHo4ghivpNJla0mmkcJanCu/JcQv2oE8TBbcZix2/W1UGDtQXJ8C9Rt4UEN383tKgz/Ppp6arWMzCGv0q01Bq9O6dMOZ3m";
	static String SUB_RA_CERT_3 = "MIIEGDCCAwCgAwIBAgIQVAMJeRoHzrj4PnxycQ1nfjANBgkqhkiG9w0BAQUFADBJMQswCQYDVQQGEwJWTjEOMAwGA1UEBxMFSGFub2kxGTAXBgNVBAoTEEJrYXYgQ29ycG9yYXRpb24xDzANBgNVBAMTBkJrYXZDQTAeFw0xNTA2MjAyMzI0MDdaFw0xNjA2MTkyMzI0MDdaMIGPMR4wHAYKCZImiZPyLGQBAQwOTVNUOjAyMDA5MDk1OTMxNTAzBgNVBAMMLEPDtG5nIFR5IEPhu5UgUGjhuqduIFRoxrDGoW5nIE3huqFpIFbEqW5oIFZ5MRIwEAYDVQQHDAlMw6ogQ2jDom4xFTATBgNVBAgMDEjhuqNpIFBow7JuZzELMAkGA1UEBhMCVk4wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAKTPOek4HQ9Chd3Xm+Dy9SgnEmhj0pjIkPNcwnBI5wLa6NQ8VbbLmu2862J05TNsr08/LrsMGKC57g87p7028aLR5HUXrExOK2+YgpaMmZw4VSBhlfPZM/K+ANjRooBN164Nz/8nk/EhxY9VxFgJvwSJNHuX1gcGc2leMl6K0AnfAgMBAAGjggE3MIIBMzAxBggrBgEFBQcBAQQlMCMwIQYIKwYBBQUHMAGGFWh0dHA6Ly9vY3NwLmJrYXZjYS52bjAdBgNVHQ4EFgQUIKt0BcolkINBN6/UlQnvmJPL1bowDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBQesA9Il9/Qw2enRoQ7WDuIDVOUhjB/BgNVHR8EeDB2MHSgI6Ahhh9odHRwOi8vY3JsLmJrYXZjYS52bi9Ca2F2Q0EuY3Jsok2kSzBJMQ8wDQYDVQQDDAZCa2F2Q0ExGTAXBgNVBAoMEEJrYXYgQ29ycG9yYXRpb24xDjAMBgNVBAcMBUhhbm9pMQswCQYDVQQGEwJWTjAOBgNVHQ8BAf8EBAMCB4AwHwYDVR0lBBgwFgYIKwYBBQUHAwQGCisGAQQBgjcKAwwwDQYJKoZIhvcNAQEFBQADggEBAHdy3LzE3+5op+YipX82IP383AlKW0zeK4/K4A+LLdRwpkbahbbYZPsO1J9E3dBY5piKy644Ff/hSwgzfX9ZqiALRf2sGDfoG0DWOLB0sSCsarBsKwmMe5lcQojB3F3C3P5kAqURVYPYGLgUkyjTVFp866fQAPZ6D0I4c832dbD4fPx81OTuXxRSiRG9I3SeGMrxs1cHCAHWALvLwbgI9/NTGqFJMfGY2WGKskNBqydqxEJPiRxCqf2JkVs35wVZofM68r58OYl4SQnJaRySInH9nPvItnFKRYjAI3oiehhdeDzXM763kQjjWE9R/Zb3++INxkNrZJ8t6K33JYvZ58M=";
	static String SUB_RA_CERT_2 = "MIIEHzCCAwegAwIBAgIQVANw4UlPXfr43CWcIUYVpjANBgkqhkiG9w0BAQUFADBJMQswCQYDVQQGEwJWTjEOMAwGA1UEBxMFSGFub2kxGTAXBgNVBAoTEEJrYXYgQ29ycG9yYXRpb24xDzANBgNVBAMTBkJrYXZDQTAeFw0xNTA2MjAyMzI0MzhaFw0xNjA2MTkyMzI0MzhaMIGWMR4wHAYKCZImiZPyLGQBAQwOTVNUOjAyMDA2NDg3MTExOTA3BgNVBAMMMEPDtG5nIFR5IEPhu5UgUGjhuqduIFRoxrDGoW5nIE3huqFpIE1p4buBbiBC4bqvYzEVMBMGA1UEBwwMTmfDtCBRdXnhu4FuMRUwEwYDVQQIDAxI4bqjaSBQaMOybmcxCzAJBgNVBAYTAlZOMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCuONjk43L6lKGYKFGRCx9w/wowfpKM4vPx5SYlNBaiq6C8+H6EHalUMLgYpyob9iPhh+HmKBWDR08FAojrDTpKvAWJBOPG60rkPFoo+NExbIcc61GcdEiBAzOHZEAMI0hoCRA9LLCCMjLU4P0AAaL4H7FCAR8T2GWiqA5IePlRvQIDAQABo4IBNzCCATMwMQYIKwYBBQUHAQEEJTAjMCEGCCsGAQUFBzABhhVodHRwOi8vb2NzcC5ia2F2Y2Eudm4wHQYDVR0OBBYEFK1znt/rvwdaMADClYBIk6V7z1tvMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUHrAPSJff0MNnp0aEO1g7iA1TlIYwfwYDVR0fBHgwdjB0oCOgIYYfaHR0cDovL2NybC5ia2F2Y2Eudm4vQmthdkNBLmNybKJNpEswSTEPMA0GA1UEAwwGQmthdkNBMRkwFwYDVQQKDBBCa2F2IENvcnBvcmF0aW9uMQ4wDAYDVQQHDAVIYW5vaTELMAkGA1UEBhMCVk4wDgYDVR0PAQH/BAQDAgeAMB8GA1UdJQQYMBYGCCsGAQUFBwMEBgorBgEEAYI3CgMMMA0GCSqGSIb3DQEBBQUAA4IBAQB576Qyl7opDWM7BoTvWUeEblRx4D5v5RAoxHrSAi6HrIQbza+8hJU56VqbVJWKHyiaawdJ9GKC8heUc75YzIenqqP7U6/P3pm95VPyHIZXayCtJBS2VHBDwWYSl+cEKBOAJyI8PKiQL1nhix5mFXYlO1i5i4Wc+HuQbadtG473WAXYXgwhx6jr6xCaD3LlwGC5/7JwJNZ1+hLk0yRZbGPYsDa6e500LAz1kQCnKJVczCMomaMB8ePuHLlm6HBa2DWh2A4be/O4X2dgPGCt1J+G7pntKM4Ejswi5eCgtos7GXbBgs26o8Unf4iAKunfiQ+tq4NyBYrs1fqD5Lg5ztgS";

	public static void main(String[] args) {
		testCertOK();
	}

	public static void checkCertificate(String base64CertData) {
		try {
			X509Certificate x509Cert = getCertFromBase64(base64CertData);
			int code = CertificateValidator.verify(x509Cert, null, new Date(),
					true, CertificateValidator.ONLY_CRL);
			System.out.println("" + code + ": "
					+ CertificateValidator.getVerifyErrorName(code));
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (BkavSignaturesException e) {
			e.printStackTrace();
		}
	}

	private static X509Certificate getCertFromBase64(String input)
			throws BkavSignaturesException, CertificateException {
		X509Certificate result = null;
		if (!isBase64(input)) {
			LOG.error("Invalid Certificate data");
			throw new BkavSignaturesException("Invalid Certificate data");
		}
		byte[] inputBytes = Base64.decode(input);
		ByteArrayInputStream inStream = new ByteArrayInputStream(inputBytes);
		try {
			CertificateFactory factory = CertificateFactory.getInstance("X509");
			Certificate cert = factory.generateCertificate(inStream);
			if (cert instanceof X509Certificate) {
				result = (X509Certificate) cert;
			}
		} catch (CertificateException e) {
			LOG.error("" + e.getMessage());
			throw e;
		}
		return result;
	}

	private static boolean isBase64(String input) {
		String pattern = "^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$";
		Pattern regex = Pattern.compile(pattern);
		Matcher matcher = regex.matcher(input);
		return matcher.matches();
	}

	public static void crossCertificateTest1() {
		String certPath = "S:/WORK/2016/01-2016/ClientCA1.cer";
		try {
			CertificateFactory factory = CertificateFactory.getInstance("X509");
			X509Certificate clientCert = (X509Certificate) factory
					.generateCertificate(
							new FileInputStream(new File(certPath)));

			Date signingTime = createDate(2016, 01, 10);
			int code = CertificateValidator.verify(clientCert, null,
					signingTime);
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
		CryptoToken token = null;
		try {
			token = CryptoTokenUtil.initFromTokenCSP(serial);
		} catch (BkavSignaturesException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// Not before: 2015/04/16 Not after: 2015/07/14 Revoked: 2015/05/27
		// 16:38:05
		if (token != null) {
			X509Certificate signerCert = token.getSignerCert();
			Certificate[] certChain = token.getCertChain();
			System.out.println(signerCert.getNotBefore());
			System.out.println(signerCert.getNotAfter());

			Date signingTime = createDate(2015, 8, 18);

			CertificateValidator.verify(signerCert, certChain, signingTime,
					CertificateValidator.ONLY_CRL);
		}
	}

	public static void testCertRevoked() {
		String keystorePath = "E:\\Company\\BKAV\\Code_Demo\\540346B323887B4E02744AC4EC6D4460_Revoked_d3jpWqicAsRZ.p12";
		String keystorePass = "d3jpWqicAsRZ";
		// String keystorePath = "S:/WORK/2015/12-2015/BCSE_Client.p12";
		// String keystorePass = "12345678";
		FileInputStream inStream = null;
		try {
			inStream = new FileInputStream(new File(keystorePath));
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
		CryptoToken token = null;
		try {
			token = CryptoTokenUtil.initFromPkcs12(inStream, keystorePass);
		} catch (BkavSignaturesException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// Not before: 2015/04/16 Not after: 2015/07/14 Revoked: 2015/05/27
		// 16:38:05
		X509Certificate signerCert = token.getSignerCert();
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
