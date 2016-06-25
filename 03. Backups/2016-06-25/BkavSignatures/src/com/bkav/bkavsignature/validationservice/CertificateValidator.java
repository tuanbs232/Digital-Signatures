package com.bkav.bkavsignature.validationservice;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import org.apache.log4j.Logger;

public class CertificateValidator {
	// Logger for this class
	private final static Logger LOG = Logger
			.getLogger(CertificateValidator.class);

	private final static String CROSS_CER_DIR_WIN = "C:/BkavCA/Certificates/CrossCertificates";
	private final static String CROSS_CER_DIR_LINUX = "/BkavCA/Certificates/CrossCertificates";

	private final static String BKAVCA_CER_DIR_WIN = "C:/BkavCA/Certificates";
	private final static String BKAVCA_CER_DIR_LINUX = "/BkavCA/Certificates";

	public static final int ONLY_OCSP = 1;
	public static final int ONLY_CRL = 2;
	public static final int BOTH_OCSP_CRL = 3;

	public static String log;

	public static int verify(X509Certificate signerCert,
			Certificate[] certChain, Date signingTime, boolean checkRevoked,
			int ocspOrCRL) {
		log = "";
		// Return verify code
		int result = 0;

		// Kiem tra chung thu null, han su dung, key usage
		int preCheck = preCheck(signerCert, certChain, signingTime);
		if (preCheck != 0) {
			LOG.error(log);
			return preCheck;
		}

		Certificate[] chainForTrustPathVerify = certChain;
		if (chainForTrustPathVerify == null
				|| chainForTrustPathVerify.length == 1) {
			chainForTrustPathVerify = createCertChainFromFile(signerCert);
		}

		// Kiem tra Trust path
		int trustPathValid = TrustPathValidator.validate(signerCert,
				chainForTrustPathVerify, signingTime);

		if (trustPathValid != 0) {
			log += "\n\tTRUSTPATH: INVALID";
			LOG.error(log);
			return ValidationError.TRUSTPATH_INVALID;
		}

		if (checkRevoked) {
			// Kiem tra trang thai revoked
			boolean getIssuerWithCrossCert = true;
			X509Certificate issuerCert = getIssuerCertificate(signerCert,
					certChain, getIssuerWithCrossCert);

			result = getRevocationStatus(signerCert, issuerCert, signingTime,
					ocspOrCRL);

			if (result == 0) {
				log += "\n\tREVOCATION: DONE";
			}
		} else{
			log += "\n\t[WARNING] Revocation not checked.";
		}
		LOG.info(log);
		return result;
	}
	
	/**
	 * Verify certificate all steps. Revocation status by OCSP or CRL pass by
	 * parameter
	 * 
	 * @param signerCert
	 *            Certificate need verify
	 * @param certChain
	 *            All certificate path from signer's certificate to trust anchor
	 * @param signingTime
	 *            Time to check certificate
	 * @param ocspOrCRL
	 *            1: Check OCSP only. 2: Check CRL only. 3: Check OCSP first, if
	 *            ocsp url not found, try to check CRL
	 * @return verify code
	 */
	public static int verify(X509Certificate signerCert,
			Certificate[] certChain, Date signingTime, int ocspOrCRL) {
		// Return verify code
		log = "";
		int result = 0;

		// Kiem tra chung thu null, han su dung, key usage
		int preCheck = preCheck(signerCert, certChain, signingTime);
		if (preCheck != 0) {
			LOG.error(log);
			return preCheck;
		}

		Certificate[] chainForTrustPathVerify = certChain;
		if (chainForTrustPathVerify == null
				|| chainForTrustPathVerify.length == 1) {
			chainForTrustPathVerify = createCertChainFromFile(signerCert);
		}

		// Kiem tra Trust path
		int trustPathValid = TrustPathValidator.validate(signerCert,
				chainForTrustPathVerify, signingTime);

		if (trustPathValid != 0) {
			log += "\n'\t[ERROR] TRUSTPATH: INVALID";
			LOG.error(log);
			return ValidationError.TRUSTPATH_INVALID;
		}
		// Kiem tra trang thai revoked
		boolean getIssuerWithCrossCert = true;
		X509Certificate issuerCert = getIssuerCertificate(signerCert, certChain,
				getIssuerWithCrossCert);

		result = getRevocationStatus(signerCert, issuerCert, signingTime,
				ocspOrCRL);

		if (result == 0) {
			log += "\n\tREVOCATION: DONE";
		}
		LOG.info(log);
		return result;
	}

	/**
	 * Verify certificate all steps. Revocation status using OCSP default
	 * 
	 * @param signerCert
	 *            Certificate need verify
	 * @param certChain
	 *            All certificate path from signer's certificate to trust anchor
	 * @param signingTime
	 *            Time to check certificate
	 * @return verify code
	 */
	public static int verify(X509Certificate signerCert,
			Certificate[] certChain, Date signingTime) {
		log = "";
		// Return verify code
		int result = 0;

		int preCheck = preCheck(signerCert, certChain, signingTime);

		if (preCheck != 0) {

			return preCheck;
		}

		Certificate[] chainForTrustPathVerify = certChain;
		if (chainForTrustPathVerify == null
				|| chainForTrustPathVerify.length == 1) {
			chainForTrustPathVerify = createCertChainFromFile(signerCert);
		}

		// Kiem tra Trust path
		int trustPathValid = TrustPathValidator.validate(signerCert,
				chainForTrustPathVerify, signingTime);

		if (trustPathValid != 0) {
			log += "\n'\t[ERROR] TRUSTPATH: INVALID";
			LOG.error(log);
			return -4;
		}

		// Kiem tra trang thai revoked(bi thu hoi)
		boolean getIssuerWithCrossCert = true;
		X509Certificate issuerCert = getIssuerCertificate(signerCert, certChain,
				getIssuerWithCrossCert);

		result = getRevocationStatus(signerCert, issuerCert, signingTime,
				ONLY_OCSP);

		if (result == 0) {
			log += "\n\tREVOCATION: DONE";
		}
		LOG.info(log);
		return result;
	}

	/**
	 * Check certificate null, check validity and check key usage
	 * 
	 * @param signerCert
	 *            X509Certificate object need to check
	 * @param signingTime
	 *            Time to check (signing time)
	 * @return status code
	 */
	private static int preCheck(X509Certificate signerCert,
			Certificate[] certChain, Date signingTime) {
		if (signerCert == null) {
			log += "NO CERTIFICATE FOUND";
			LOG.error(log);
			return 7;
		}

		log += "VERIFY CERTIFICATE: " + signerCert.getSerialNumber() + " - "
				+ signerCert.getSubjectDN();

		// Kiem tra han su dung
		try {
			signerCert.checkValidity(signingTime);
			log += "\n\tVALIDITY: DONE";
		} catch (CertificateExpiredException e) {
			log += "\n\t[ERROR] VALIDITY: Expired at signing time";
			return 2;
		} catch (CertificateNotYetValidException e) {
			log += "\n\t[ERROR] VALIDITY: Not yet valid at signing time";
			return 1;
		}

		boolean getNewCAWithCrossCert = true;

		X509Certificate issuerCert = getIssuerCertificate(signerCert, certChain,
				getNewCAWithCrossCert);

		boolean verifyCode = false;
		if (issuerCert == null) {
			return ValidationError.SIGNATURE_INVALID;
		}
		try {
			signerCert.verify(issuerCert.getPublicKey());
			verifyCode = true;
			log += "\n\tISSUER'S SIGNATURE: DONE";
		} catch (InvalidKeyException e1) {
		} catch (CertificateException e1) {
		} catch (NoSuchAlgorithmException e1) {
		} catch (NoSuchProviderException e1) {
		} catch (SignatureException e1) {
		}

		if (!verifyCode) {
			return ValidationError.CERTIFICATE_SIGNATURE_FAILED;
		}

		// Kiem tra key usage
		boolean keyUsage = checkKeyUsage(signerCert);
		if (keyUsage) {
			log += "\n\tKEY USAGE: DONE";
		} else {
			log += "\n\t[ERROR] KEY USAGE: Key usage not obtain Digital signature.";

			return 3;
		}

		return 0;
	}

	/**
	 * Get revocation information of signer's certificate
	 * 
	 * @param signerCert
	 *            X509Certificate object need get information
	 * @param issuerCert
	 *            Issuer's certificate
	 * @param signingTime
	 *            Time to check revocation information (signing time)
	 * @param ocspOrCrl
	 *            1: only check OCSP. 2: only check CRL. 3: Check ocsp first, if
	 *            ocsp url not found, try to check CRL
	 * @return revocation status code
	 */
	private static int getRevocationStatus(X509Certificate signerCert,
			X509Certificate issuerCert, Date signingTime, int ocspOrCrl) {
		// Get revocation status by CRL
		if (ocspOrCrl == ONLY_CRL) {

			return CRLValidator.getRevocationStatus(signerCert, issuerCert,
					signingTime, true);
		}
		// Get revocation status by OCSP
		if (ocspOrCrl == ONLY_OCSP) {
			return OCSPValidator.getRevocationStatus(signerCert, issuerCert,
					signingTime);
		}
		// Get revocation status by OCSP first. If ocsp url not found, try to
		// get by CRL
		if (ocspOrCrl == BOTH_OCSP_CRL) {
			int result = OCSPValidator.getRevocationStatus(signerCert,
					issuerCert, signingTime);
			if (result == ValidationError.OCSP_URL_NOT_FOUND
					|| result == ValidationError.OCSP_RESPONSE_NULL
					|| result == ValidationError.OCSP_RESPONDER_NOT_FOUND
					|| result == ValidationError.OCSP_SIGNATURE_INVALID) {
				result = CRLValidator.getRevocationStatus(signerCert,
						issuerCert, signingTime, true);
			}

			return result;
		}

		return OCSPValidator.UNKNOWN_STATUS;
	}

	/**
	 * Check signer's certificate key usage
	 * 
	 * @param cert
	 *            Signer's certificate
	 * @return true neu keyusage co Digital Signature false neu nguoc lai
	 */
	private static boolean checkKeyUsage(X509Certificate cert) {
		boolean[] keyUsage = cert.getKeyUsage();

		return keyUsage[0];
	}

	/**
	 * Get issuer certificate from signer's certificate and certificate chain
	 * 
	 * @param signerCert
	 *            X509Certificate object
	 * @param certChain
	 *            Chain from signer's certificate to trust anchor
	 * @return a X509Certificate object if available or null
	 */
	private static X509Certificate getIssuerCertificate(
			X509Certificate signerCert, Certificate[] certChain,
			boolean cross) {
		X509Certificate result = null;

		// Try get from chain
		result = getIssuerFromChain(signerCert, certChain);

		boolean issuerValid = false;
		if (result != null) {
			try {
				result.checkValidity();
				issuerValid = true;
			} catch (CertificateExpiredException e) {
				log += "\n'\tISSUER FROM CHAIN EXPIRED. TRY GET FROM DIRECTORY /BkavCA/Certificates/";
			} catch (CertificateNotYetValidException e) {
			}
		}

		// Try get from file /BkavCA/BkavCA.cer
		if (result == null || !issuerValid) {
			String issuerPath = "";
			String osName = System.getProperty("os.name");
			if (osName.contains("Windows")) {
				issuerPath = BKAVCA_CER_DIR_WIN;
			} else if (osName.contains("Linux")) {
				issuerPath = BKAVCA_CER_DIR_LINUX;
			}
			result = getIssuerFromFile(signerCert, issuerPath);
			if (result != null) {
				try {
					result.checkValidity();
					issuerValid = true;
				} catch (CertificateExpiredException e) {
					log += "\n'\tIssuer from file was expired. Trying with cross certificate";
				} catch (CertificateNotYetValidException e) {
				}
			}
		}

		if (cross) {
			if (result == null || !issuerValid) {
				result = getIssuerFromFileWithCross(signerCert);
			}
		}

		// Try get from url
		if (result == null) {
			result = getIssuerFromURL(signerCert);
		}

		return result;
	}

	/**
	 * Get issuer's certificate from Authority Information Access extension
	 * value
	 * 
	 * @param signserCert
	 *            Signer's certificate
	 * @return X509Certificate object if available or null
	 */
	private static X509Certificate getIssuerFromURL(
			X509Certificate signserCert) {
		X509Certificate result = null;
		String caCertUrl = OCSPValidator.getIssuerCertURL(signserCert);
		if (caCertUrl == null || caCertUrl.equals("")) {

			return null;
		}

		HttpURLConnection con = null;
		URL url;
		try {
			url = new URL((String) caCertUrl);
			con = (HttpURLConnection) url.openConnection();
			con.setRequestProperty("Content-Type",
					"application/x-x509-ca-cert");
			con.setRequestProperty("Accept", "application/x-x509-ca-cert");
			con.setDoOutput(true);

			if (con.getResponseCode() / 100 != 2) {
				return null;
			}

			InputStream in = (InputStream) con.getContent();
			CertificateFactory certFactory = CertificateFactory
					.getInstance("X509");
			Certificate cert = certFactory.generateCertificate(in);

			if (cert != null && cert instanceof X509Certificate) {
				result = (X509Certificate) cert;
			}
		} catch (MalformedURLException e) {
			log += "\n'\t[ERROR] Cannot get issuer from web. Network error"
					+ e.getMessage();
		} catch (IOException e) {
			log += "\n'\t[ERROR] Cannot get issuer from web. Network error. "
					+ e.getMessage();
		} catch (CertificateException e) {
			log += "\n'\t[ERROR] Cannot get issuer from web. " + e.getMessage();
		}

		return result;
	}

	/**
	 * Get issuer certificate from certchain if available
	 * 
	 * @param signerCert
	 *            Signer's Certificate
	 * @param certChain
	 *            Certificate chain from signed document or somewhere
	 * @return issuer's certificate if available or null if not
	 */
	private static X509Certificate getIssuerFromChain(
			X509Certificate signerCert, Certificate[] certChain) {
		X509Certificate result = null;

		if (certChain == null || certChain.length == 0) {
			LOG.info("No certchain found. Try get from file");
			return null;
		}

		for (Certificate issuerCert : certChain) {
			if (issuerCert instanceof X509Certificate) {
				X509Certificate cert = (X509Certificate) issuerCert;
				if (cert.getSubjectX500Principal()
						.equals(signerCert.getIssuerX500Principal())) {
					result = cert;
					break;
				}
			}
		}

		return result;
	}

	private static X509Certificate getIssuerFromFileWithCross(
			X509Certificate signerCert) {
		String issuerPath = "";
		String crossPath = "";
		String osName = System.getProperty("os.name");
		if (osName.contains("Windows")) {
			crossPath = CROSS_CER_DIR_WIN;
			issuerPath = BKAVCA_CER_DIR_WIN;
		} else if (osName.contains("Linux")) {
			crossPath = CROSS_CER_DIR_LINUX;
			issuerPath = BKAVCA_CER_DIR_LINUX;
		}

		X509Certificate crossCert = getIssuerFromFile(signerCert, crossPath);
		if (crossCert == null) {
			LOG.error("No cross CA certificate for "
					+ getSubjectName(signerCert));
			return null;
		}

		return getIssuerFromFile(crossCert, issuerPath);
	}

	/**
	 * Get issuer certificate from file /BkavCA/Cetificates/
	 * 
	 * @param signerCert
	 *            Signer's certificate
	 * @return X509 Certificate object if available or may be null
	 */
	private static X509Certificate getIssuerFromFile(X509Certificate signerCert,
			String path) {
		X509Certificate result = null;
		try {
			CertificateFactory certFactory = CertificateFactory
					.getInstance("X509");

			String issuerCertDir = path;

			File containFolder = new File(issuerCertDir);

			for (final File fileEntry : containFolder.listFiles()) {
				if (!fileEntry.isDirectory()
						&& fileEntry.getName().endsWith(".cer")) {
					FileInputStream inStream = new FileInputStream(new File(
							issuerCertDir + "/" + fileEntry.getName()));

					Certificate issuerCert = certFactory
							.generateCertificate(inStream);

					if (issuerCert instanceof X509Certificate) {
						X509Certificate cert = (X509Certificate) issuerCert;
						if (cert.getSubjectX500Principal()
								.equals(signerCert.getIssuerX500Principal())) {

							result = cert;
							break;
						}
					}
				}
			}

		} catch (CertificateException e) {
			log += "\n'\t[ERROR] Cannot get issuer from file.";
			return null;
		} catch (FileNotFoundException e) {
			log += "\n'\t[ERROR] Issuer certificate file not found.";
			return null;
		}

		return result;
	}

	/**
	 * Create certificate chain to root CA from directory /BkavCA/Certificates
	 * 
	 * @param signerCert
	 *            signer's certificate
	 * @return Array of Certificate object if available or may be null
	 */
	public static Certificate[] createCertChainFromFile(
			X509Certificate signerCert) {
		List<Certificate> result = new ArrayList<Certificate>();

		boolean foundRootCA = false;
		try {
			CertificateFactory certFactory = CertificateFactory
					.getInstance("X509");

			String issuerCertDir = "";
			String osName = System.getProperty("os.name");
			if (osName.contains("Windows")) {
				issuerCertDir = BKAVCA_CER_DIR_WIN;
			} else if (osName.contains("Linux")) {
				issuerCertDir = BKAVCA_CER_DIR_LINUX;
			}

			File containFolder = new File(issuerCertDir);

			X509Certificate currentCA = signerCert;
			result.add(currentCA);
			while (!isTrustAnchor(currentCA)) {
				boolean found = false;
				for (final File fileEntry : containFolder.listFiles()) {
					if (!fileEntry.isDirectory()
							&& fileEntry.getName().endsWith(".cer")) {
						FileInputStream inStream = new FileInputStream(new File(
								issuerCertDir + "/" + fileEntry.getName()));

						Certificate issuerCert = certFactory
								.generateCertificate(inStream);

						if (issuerCert instanceof X509Certificate) {
							X509Certificate cert = (X509Certificate) issuerCert;
							if (cert.getSubjectX500Principal().equals(
									currentCA.getIssuerX500Principal())) {
								try {
									currentCA.verify(cert.getPublicKey());
									result.add(cert);
									currentCA = cert;
									found = true;
									break;
								} catch (InvalidKeyException e) {
								} catch (NoSuchAlgorithmException e) {
								} catch (NoSuchProviderException e) {
								} catch (SignatureException e) {
								}
								continue;
							}
						}
					}
				}
				if (!found) {
					break;
				}
				if (currentCA.getSubjectX500Principal()
						.equals(currentCA.getIssuerX500Principal())) {
					foundRootCA = true;
					break;
				}
			}

		} catch (CertificateException e) {
			log += "\n\t[ERROR] Cannot create certchain from file.";

			return null;
		} catch (FileNotFoundException e) {
			log += "\n\t[ERROR] Cannot create certchain from file.";

			return null;
		}

		if (foundRootCA) {
			Certificate[] certChain = new Certificate[result.size()];
			certChain = result.toArray(certChain);

			return certChain;
		} else {
			log += "\n\t[ERROR] Cannot create certchain from file. Root CA not found";
			return null;
		}
	}

	private static boolean isTrustAnchor(X509Certificate cert) {
		return cert.getSubjectX500Principal()
				.equals(cert.getIssuerX500Principal());
	}

	private static String getSubjectName(X509Certificate signerCert) {
		String result = "";
		LdapName ldap;
		try {
			ldap = new LdapName(signerCert.getSubjectDN().getName());
			List<Rdn> rdns = ldap.getRdns();
			for (Rdn rdn : rdns) {
				if (rdn.getType().equalsIgnoreCase("CN")) {
					result = rdn.getValue().toString();
					break;
				}
			}
		} catch (InvalidNameException e) {
			// Khong can phai log
		}

		return result;
	}

	/**
	 * Get signature verify result message
	 * 
	 * @param code 
	 * @return
	 */
	public static String getVerifyErrorName(int code) {
		String result = "";
		switch (code) {
		case 0:
			result = "OK";
			break;
		case -1:
			result = "Không load được dữ liệu";
			break;
		case -2:
			result = "Không tìm thấy chữ ký trong tài liệu";
			break;
		case -3:
			result = "Chữ ký không hợp lệ";
			break;
		case -4:
			result = "Không thể kiểm tra được đường dẫn tin tưởng";
			break;
		case -5:
			result = "Không đủ thông tin để kiểm tra. Không tìm thấy chứng thư số của CA";
			break;
		case ValidationError.CERTIFICATE_EXPIRED:
			result = "Chữ ký số đã hết hạn tại thời điểm ký";
			break;
		case ValidationError.CERTIFICATE_NOT_YET_VALID:
			result = "Chữ ký số chưa có hiệu lực tại thời điểm ký";
			break;
		case ValidationError.CERTIFICATE_STATUS_REVOKED:
			result = "Chữ ký số đã bị thu hồi tại thời điểm ký";
			break;
		case ValidationError.CRL_NOT_FOUND:
			result = "Không tìm thấy CRL.";
		break;
		default:
			result = "UNDEFINDED";
			break;
		}
		return result;
	}
}
