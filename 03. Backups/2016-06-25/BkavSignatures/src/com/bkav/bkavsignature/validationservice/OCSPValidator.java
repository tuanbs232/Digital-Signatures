package com.bkav.bkavsignature.validationservice;

import java.io.BufferedOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.ocsp.OCSPRespStatus;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

public class OCSPValidator {
	private final static Logger LOG = Logger.getLogger(OCSPValidator.class);

	public final static int OCSP_URL_NOT_FOUND = 6;
	public final static int OCSP_RESPONSE_NULL = 8;
	public final static int CERT_GOOD_WHEN_SIGN = 0;
	public final static int CERT_REVOKED_WHEN_SIGN = 4;
	public final static int UNKNOWN_STATUS = 5;

	public final static String SHA_256_OID = "2.16.840.1.101.3.4.2.1";

	final static String OCSP_OID = "1.3.6.1.5.5.7.48.1"; // neu la .1 thi chuyen
															// den OCSP
	final static String ISSUER_CERT_OID = "1.3.6.1.5.5.7.48.2"; // Neu la .2 thi
																// chuyen den
																// link cua CA

	public static final String OCSP_SIGNER = "1.3.6.1.5.5.7.3.9";

	/**
	 * Get revocation information of signer's certificate
	 * 
	 * @param clientCert
	 *            signer's certificate
	 * @param issuerCert
	 *            issuer's certificate
	 * @param signingTime
	 *            time need to check revocation information
	 * @return verify code
	 */
	public static int getRevocationStatus(X509Certificate clientCert,
			X509Certificate issuerCert, Date signingTime) {
		if (clientCert == null || issuerCert == null) {
			CertificateValidator.log += "\n\t[ERROR] Signer's certificate or "
					+ "issuer's certificat not found";
			return ValidationError.SIGNER_CERTIFICATE_NOT_FOUND;
		}

		OCSPReq request = generateOCSPReqest(issuerCert,
				clientCert.getSerialNumber());

		if (request == null) {
			CertificateValidator.log += "\n\tREVOCATION: [ERROR] Cannot generate "
					+ "OCSP request";
			return ValidationError.CANNOT_CREATE_OCSP_REQUEST;
		}

		String serviceAddr = getOCSPURL(clientCert);

		// Return error if OCSP url not found
		if (serviceAddr == null || "".equals(serviceAddr)) {
			CertificateValidator.log += "\n\tREVOCATION: [ERROR] OCSP responder "
					+ "url not found.";
			return ValidationError.OCSP_URL_NOT_FOUND;
		}

		// Get ocsp response from responder
		OCSPResp response = getOCSPResponse(serviceAddr, request);

		if (response == null) {
			return ValidationError.OCSP_RESPONSE_NULL;
		}

		if (response.getStatus() != OCSPRespStatus.SUCCESSFUL) {
			CertificateValidator.log += "\n\tREVOCATION: [ERROR] OCSP Response "
					+ "Status Received " + response.getStatus();

			return ValidationError.OCSP_RESPONSE_NULL;
		}

		BasicOCSPResp basicResponse = null;
		try {
			basicResponse = (BasicOCSPResp) response.getResponseObject();
		} catch (OCSPException e) {
			LOG.error("REVOCATION: [ERROR] Cannot parse OCSP response");

			return ValidationError.OCSP_RESPONSE_NULL;
		}

		// Get responder's certificate and verify it
		X509Certificate ocspResponderCert = getOCSPResponderCert(issuerCert,
				basicResponse);
		if (ocspResponderCert == null) {
			CertificateValidator.log += "\n\tREVOCATION: [ERROR] Cannot verify "
					+ "response signature. " + "No responder certificate found";
			return ValidationError.OCSP_RESPONDER_NOT_FOUND;
		}

		if (!verifyOCSPResponderCertificate(ocspResponderCert)) {
			return ValidationError.OCSP_SIGNATURE_INVALID;
		}

		SingleResp[] responses = (basicResponse == null) ? null
				: basicResponse.getResponses();

		if (responses == null) {
			CertificateValidator.log += "\n\tREVOCATION: [ERROR] Responder's "
					+ "certificate not found";
			return ValidationError.OCSP_RESPONSE_NULL;
		}

		boolean responseExist = false;
		for (SingleResp resp : responses) {
			// TODO: Kiem tra match giua request va response thong qua
			// CertificateID
			// --> Cam thay khong can thiet, mat thoi gian
			responseExist = true;

			Object status = resp.getCertStatus();
			if (status == CertificateStatus.GOOD) {

				return ValidationError.CERTIFICATE_STATUS_GOOD;
			} else if (status instanceof RevokedStatus) {
				RevokedStatus revokedStatus = (RevokedStatus) status;

				SimpleDateFormat df = new SimpleDateFormat(
						"yyyy/MM/dd HH:mm:ss");
				String revocationDate = df
						.format(revokedStatus.getRevocationTime());

				if (signingTime.before(revokedStatus.getRevocationTime())) {
					CertificateValidator.log += "\n\tREVOCATION: Certificat "
							+ "good at signing time, but revoked now.\nRevoked at: "
							+ revocationDate + "\nRevocation reason: "
							+ getRevocationReason(
									revokedStatus.getRevocationReason());
					return ValidationError.CERTIFICATE_STATUS_GOOD;
				} else {
					CertificateValidator.log += "\n\tREVOCATION: Certificate revoked"
							+ " at signing time.\nRevoked at: " + revocationDate
							+ "\nRevocation reason: " + getRevocationReason(
									revokedStatus.getRevocationReason());
					return ValidationError.CERTIFICATE_STATUS_REVOKED;
				}
			} else if (status instanceof UnknownStatus) {
				return ValidationError.CERTIFICATE_STATUS_UNKNOWN;
			}
		}

		if (!responseExist) {
			CertificateValidator.log += "\n\t[ERROR] No response match OCSP request";
			return ValidationError.OCSP_RESPONSE_NULL;
		}

		return ValidationError.SIGNATURE_VALID;
	}

	/**
	 * Verify OCSP Responder's certificate
	 * 
	 * @param responderCert
	 *            Responder's certificate
	 * @return true if all OK, false if otherwise
	 */
	private static boolean verifyOCSPResponderCertificate(
			X509Certificate responderCert) {
		if (responderCert.getExtensionValue(
				OCSPObjectIdentifiers.id_pkix_ocsp_nocheck.getId()) != null) {
			try {
				responderCert.checkValidity();
				return true;
			} catch (CertificateExpiredException e) {
				CertificateValidator.log += "\n\t[ERROR] OCSP Responder's certificte expired";
				return false;
			} catch (CertificateNotYetValidException e) {
				CertificateValidator.log += "\n\t[ERROR] OCSP Responder's certificte not yet valid";
				return false;
			}
		} else {
			// TODO: Can kiem tra tinh trang revoked o day thong qua CRL
			// TODO: Kiem tra ca viec chu ky tren responderCert co khop voi
			// issuer Public key khong
			return true;
		}
	}

	/**
	 * Get OCSP Responder's certificate from OCSP Response
	 * 
	 * @param issuer
	 *            issuer's certificate to check ocsp's signature
	 * @param basicResponse
	 *            OCSP Response
	 * @return X509Certificate if available or may be null
	 */
	private static X509Certificate getOCSPResponderCert(X509Certificate issuer,
			BasicOCSPResp basicResponse) {
		X509Certificate result = null;

		// 1. Kiem tra chu ky tren response voi certificate cua CA truyen vao,
		// neu khop thi tra ve certificate nay luon
		ContentVerifierProvider verifier;
		try {
			verifier = new JcaContentVerifierProviderBuilder().setProvider("BC")
					.build(issuer.getPublicKey());
			if (basicResponse.isSignatureValid(verifier)) {

				result = issuer;
			}
		} catch (OperatorCreationException e) {
			LOG.error("Cannot instance JcaContentVerifierProviderBuilder");
		} catch (OCSPException e) {
			LOG.error("Cannot verify OCSP response signature");
		}

		// 2. Neu CA khong ky len response, kiem tra danh sach certificate dinh
		// kem trong response de lay responder certificate
		if (result == null) {
			// 2.1 Doc tat ca certificate trong ocsp response
			X509CertificateHolder[] certs = basicResponse.getCerts();

			if (certs == null || certs.length == 0) {
				return null;
			}

			for (X509CertificateHolder cert : certs) {
				X509Certificate xcert = null;

				try {
					xcert = new JcaX509CertificateConverter()
							.getCertificate((X509CertificateHolder) cert);
				} catch (CertificateException ex) {
					continue;
				}

				// 2.2 Kiem tra xem cert co key usage la ocsp signer khong
				try {
					if (xcert.getExtendedKeyUsage() != null) {

						for (String ext : xcert.getExtendedKeyUsage()) {
							if (ext.equals(OCSP_SIGNER)) {
								result = xcert;
								break;
							}
						}
					}
				} catch (CertificateParsingException e) {
					continue;
				}

				// 2.3 Neu co thi kiem tra xem co khop voi chu ky tren response
				// thi tra ve
				try {
					if (xcert != null && basicResponse.isSignatureValid(
							new JcaContentVerifierProviderBuilder()
									.setProvider("BC")
									.build(xcert.getPublicKey()))) {
						result = xcert;
						break;
					}
				} catch (OperatorCreationException e) {
				} catch (OCSPException e) {
				}
			}
		}

		return result;
	}

	/**
	 * Generate OCSP request from issuer's certificate and signer's certificate
	 * serial number
	 * 
	 * @param issuerCert
	 *            issuer's certificate
	 * @param serialNumber
	 *            serial number of signer's certificate
	 * @return OCSPReq object if available or may be null
	 */
	public static OCSPReq generateOCSPReqest(X509Certificate issuerCert,
			BigInteger serialNumber) {
		Security.addProvider(new BouncyCastleProvider());
		DigestCalculatorProvider provider = new BcDigestCalculatorProvider();
		X509CertificateHolder holder;
		CertificateID certificateID = null;
		try {
			AlgorithmIdentifier sha256 = new AlgorithmIdentifier(
					new ASN1ObjectIdentifier(SHA_256_OID));
			holder = new X509CertificateHolder(issuerCert.getEncoded());
			
			// TODO Dang test cho nay thoi
			// certificateID = new CertificateID(
			// provider.get(CertificateID.HASH_SHA1), holder,
			// serialNumber);
			
			certificateID = new CertificateID(provider.get(sha256), holder,
					serialNumber);
		} catch (CertificateEncodingException e) {
			LOG.error("CANNOT GENERATE OCSP REQUEST ID");
			return null;
		} catch (IOException e) {
			LOG.error("CANNOT GENERATE OCSP REQUEST ID");
			return null;
		} catch (OperatorCreationException e) {
			LOG.error("CANNOT GENERATE OCSP REQUEST ID");
			return null;
		} catch (OCSPException e) {
			LOG.error("CANNOT GENERATE OCSP REQUEST ID");
			return null;
		}

		BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());

		OCSPReqBuilder builder = new OCSPReqBuilder();
		builder.addRequest(certificateID);
		ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
		try {
			extensionsGenerator.addExtension(
					OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false,
					new DEROctetString(nonce.toByteArray()));

			return builder.build();
		} catch (IOException e) {
			LOG.error("CANNOT GENERATE OCSP REQUEST ID");
			return null;
		} catch (OCSPException e) {
			LOG.error("CANNOT GENERATE OCSP REQUEST ID");
			return null;
		}
	}

	/**
	 * Get OCSP response from internet with scheme http (otherwise may be null)
	 * 
	 * @param serviceUrl
	 *            authority information access url
	 * @param request
	 *            OCSPReq object
	 * @return OCSPResp object if available or may be null
	 */
	public static OCSPResp getOCSPResponse(String serviceUrl, OCSPReq request) {
		byte[] dataRequest = null;
		try {
			dataRequest = request.getEncoded();
		} catch (IOException e) {
			LOG.error("BAD OCSP REQUEST");
			return null;
		}

		if (serviceUrl.startsWith("http")) {
			HttpURLConnection con = null;
			URL url;
			try {
				url = new URL((String) serviceUrl);
				con = (HttpURLConnection) url.openConnection();
				con.setRequestProperty("Content-Type",
						"application/ocsp-request");
				con.setRequestProperty("Accept", "application/ocsp-response");
				con.setDoOutput(true);
				OutputStream out = con.getOutputStream();
				DataOutputStream dataOut = new DataOutputStream(
						new BufferedOutputStream(out));

				dataOut.write(dataRequest);

				dataOut.flush();
				dataOut.close();

				if (con.getResponseCode() / 100 != 2) {
					return null;
				}

				InputStream in = (InputStream) con.getContent();

				return new OCSPResp(in);
			} catch (MalformedURLException e) {
				LOG.error("CANNOT CREATE URL FROM AUTHORITY INFORMATION ACCESS "
						+ serviceUrl);
				return null;
			} catch (IOException e) {
				LOG.error("CANNOT CREATE CONNECTION TO " + serviceUrl);
				return null;
			}
		} else {
			LOG.error("Only suport HTTP protocol");
			return null;
		}
	}

	/**
	 * Get Issuer Certificate url from certificate
	 * 
	 * @param cert
	 * @return
	 */
	public static String getIssuerCertURL(X509Certificate cert) {

		return getAuthorityInfoAccess(cert,
				AccessDescription.id_ad_caIssuers.getId());
	}

	/**
	 * Get ocsp url from certificate
	 * 
	 * @param cert
	 * @return
	 */
	public static String getOCSPURL(X509Certificate cert) {

		return getAuthorityInfoAccess(cert,
				AccessDescription.id_ad_ocsp.getId());
	}

	/**
	 * Get Authority Information Access from certificate new method
	 * 
	 * @param cert
	 *            X509Certificate object
	 * @param accessMethod
	 *            OID of accessMethod. OCSP: 1.3.6.1.5.5.7.48.1, ISSUER CERT:
	 *            1.3.6.1.5.5.7.48.2
	 * @return url authority information access
	 */
	private static String getAuthorityInfoAccess(X509Certificate cert,
			String accessMethod) {
		String result = null;

		byte[] octetBytes = cert
				.getExtensionValue(X509Extension.authorityInfoAccess.getId());

		if (octetBytes == null) {
			LOG.error("REVOCATION: No Authority Information Access found");
			return null;
		}

		ASN1InputStream octetStream = new ASN1InputStream(octetBytes);
		byte[] encoded = null;
		try {
			encoded = X509ExtensionUtil.fromExtensionValue(octetBytes)
					.getEncoded();
		} catch (IOException e) {
			LOG.error("CANNOT GET EXTENSIONS FROM CERTIFICATE");

			try {
				octetStream.close();
			} catch (IOException ex) {
			}

			return null;
		}

		ASN1Sequence seq = null;
		try {
			seq = ASN1Sequence
					.getInstance(ASN1Primitive.fromByteArray(encoded));
		} catch (IOException e) {
			LOG.error("CANNOT GET EXTENSIONS FROM CERTIFICATE");

			try {
				octetStream.close();
			} catch (IOException ex) {
			}

			return null;
		}

		AuthorityInformationAccess access = AuthorityInformationAccess
				.getInstance(seq);
		if (access.getAccessDescriptions()[0].getAccessMethod().toString()
				.equals(accessMethod)) {
			ASN1Encodable asn1Encodable = access.getAccessDescriptions()[0]
					.getAccessLocation().getName();
			if (asn1Encodable instanceof DERTaggedObject) {
				DERTaggedObject derTaggedObject = (DERTaggedObject) asn1Encodable;
				byte[] encoded1 = null;
				try {
					encoded1 = derTaggedObject.getEncoded();
				} catch (IOException e) {
					LOG.error("CANNOT PARSE EXTENSIONS FROM CERTIFICATE");

					result = null;
				}

				if (derTaggedObject.getTagNo() == 6) {
					int len = encoded1[1];

					result = new String(encoded, 2, len);
				}
			} else if (asn1Encodable instanceof DERIA5String) {

				DERIA5String en = (DERIA5String) asn1Encodable;

				result = en.getString();
			}
		} else {
			LOG.error("ACCESS METHOD NOT MATCH ");

			result = null;
		}

		try {
			octetStream.close();
		} catch (IOException e) {

		}

		return result;
	}

	/**
	 * Get revocation reason name
	 * 
	 * @param reason
	 *            Revocation reason code
	 * @return name of revocation reason code
	 */
	private static String getRevocationReason(int reason) {
		switch (reason) {
		case 0:
			return "UNKNOWN";
		case 1:
			return "REVOKATION_REASON_KEYCOMPROMISE";
		case 2:
			return "REVOKATION_REASON_CACOMPROMISE";
		case 3:
			return "REVOKATION_REASON_AFFILIATIONCHANGED";
		case 4:
			return "REVOKATION_REASON_SUPERSEDED";
		case 5:
			return "REVOKATION_REASON_CESSATIONOFOPERATION";
		case 6:
			return "REVOKATION_REASON_CERTIFICATEHOLD";
		case 7:
			return "UNKNOWN";
		case 8:
			return "REVOKATION_REASON_REMOVEFROMCRL";
		case 9:
			return "REVOKATION_REASON_PRIVILEGESWITHDRAWN";
		case 10:
			return "REVOKATION_REASON_AACOMPROMISE";

		default:
			return "UNKNOWN";
		}
	}
}
