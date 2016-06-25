package com.bkav.bkavsignature.validationservice;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CRLReason;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Hashtable;
import java.util.Map;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.Extension;

/**
 * Class to get revocation information of X509Certificate object
 * 
 * @author TuanBS
 *
 */
public class CRLValidator {
	// Logger for this class
	private final static Logger LOG = Logger.getLogger(CRLValidator.class);

	// Directory of BkavCA CRL distribution
	private final static String BKAVCA_CRL_DIR_WIN = "C:/BkavCA/CRLs";
	private final static String BKAVCA_CRL_DIR_LINUX = "/BkavCA/CRLs";

	// Return verify code
	final static int CERT_GOOD_WHEN_SIGN = 0;
	final static int CERT_REVOKED_WHEN_SIGN = 4;

	/**
	 * Get revocation information of X509Certificate object with signing time
	 * 
	 * @param cert
	 *            X509Certificate object need to check revocation information
	 * 
	 * @param issuer
	 *            issuer's certificate
	 * @param signingTime
	 *            Time to check
	 * @param tryFromFileFirst
	 *            if True, try check with CRL file /BkavCA/BkavCA.crl; if False,
	 *            download CRL from internet
	 * @return revocation status code
	 */
	public static int getRevocationStatus(X509Certificate cert,
			X509Certificate issuer, Date signingTime,
			boolean tryFromFileFirst) {
		int result = ValidationError.CERTIFICATE_STATUS_GOOD;
		if (cert == null) {
			return ValidationError.SIGNER_CERTIFICATE_NOT_FOUND;
		}
		if (signingTime == null) {
			signingTime = new Date();
		}

		X509CRL crl = getCRLDistribution(cert, issuer, tryFromFileFirst);
		if (crl == null) {
			CertificateValidator.log += "\n\tREVOCATION: [ERROR] NO CRL DISTRIBUTION FOUND";
			return ValidationError.CRL_NOT_FOUND;
		}

		X509CRLEntry crlEntry = crl.getRevokedCertificate(cert);
		if (crlEntry != null) {
			Date revocationDate = crlEntry.getRevocationDate();
			SimpleDateFormat df = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
			String revocationDateStr = df.format(revocationDate);
			if (signingTime.before(revocationDate)) {
				CertificateValidator.log += "\n\tREVOCATION: CERTIFICATE GOOD AT SIGNING TIME, BUT NOW REVOKED.\nRevoked at: "
								+ revocationDateStr;
				result = ValidationError.CERTIFICATE_STATUS_GOOD;
			} else {
				CertificateValidator.log += "\n\tREVOCATION: Certificate revoked at signing time.\nRevoked at: "
						+ revocationDate + "\nRevocation reason: "
						+ getRevocationReason(crlEntry.getRevocationReason());
				result = ValidationError.CERTIFICATE_STATUS_REVOKED;
			}
		}

		return result;
	}

	/**
	 * Get CRL distribution
	 * 
	 * @param cert
	 *            X509Certificat object
	 * @param tryFromFileFirst
	 *            if True, try to get BkavCA CRL from /BkavCA/BkavCA.cer first;
	 *            if False, download from internet
	 * @return X509CRL object if available or may be null
	 */
	private static X509CRL getCRLDistribution(X509Certificate cert,
			X509Certificate issuer, boolean tryFromFileFirst) {
		X509CRL result = null;
		if (tryFromFileFirst) {
			result = getCRLFromFile(cert);
		}

		if (result == null) {
			result = downloadCRL(cert);
		}
		
		if(result == null){
			return null;
		}

		try {
			result.verify(issuer.getPublicKey());
		} catch (InvalidKeyException e) {
			LOG.error("CRL NOT MATCH ISSUER CERTIFICATE");
			return null;
		} catch (CRLException e) {
			LOG.error("CRL EXCEPTION " + e.getMessage());
			return null;
		} catch (NoSuchAlgorithmException e) {
			LOG.error("NO SUCH ALGORITHM EXCEPTION " + e.getMessage());
			return null;
		} catch (NoSuchProviderException e) {
			LOG.error("NO SUCH PROVIDER EXCEPTION " + e.getMessage());
			return null;
		} catch (SignatureException e) {
			LOG.error("SIGNATURE EXCEPTION " + e.getMessage());
			return null;
		}

		return result;
	}

	/**
	 * Get BkavCA CRL distribution from file /BkavCA/BkavCA.crl
	 * 
	 * @return X509CRL object if available or may be null
	 */
	public static X509CRL getCRLFromFile(X509Certificate cert) {
		X509CRL result = null;

		CertificateFactory certFactory = null;
		try {
			certFactory = CertificateFactory.getInstance("X509");
		} catch (CertificateException e) {
			LOG.error("CANNOT INSTANCE CertificateFactory " + e.getMessage());

			return null;
		}

		String issuerCertDir = "";
		String osName = System.getProperty("os.name");
		if (osName.contains("Windows")) {
			issuerCertDir = BKAVCA_CRL_DIR_WIN;
		} else if (osName.contains("Linux")) {
			issuerCertDir = BKAVCA_CRL_DIR_LINUX;
		}

		File containFolder = new File(issuerCertDir);
		
		if(containFolder.listFiles() == null){
			LOG.error("/BkavCA/CRLs not found.");
			return null;
		}

		for (final File fileEntry : containFolder.listFiles()) {
			if (!fileEntry.isDirectory()
					&& fileEntry.getName().endsWith(".crl")) {
				;
				FileInputStream inStream = null;
				try {
					inStream = new FileInputStream(
							new File(issuerCertDir + "/" + fileEntry.getName()));
				} catch (FileNotFoundException e) {
					LOG.error("CRL FILE NOT FOUND EXCEPTION");
					continue;
				}

				X509CRL crl;
				try {
					crl = (X509CRL) certFactory.generateCRL(inStream);

					if (cert.getIssuerX500Principal()
							.equals(crl.getIssuerX500Principal())) {

						result = crl;
						break;
					}
				} catch (CRLException e) {
					LOG.error("CRL EXCEPTION " + e.getMessage());
					continue;
				}
			}
		}
		
		return result;
	}

	/**
	 * Download CRL distribution from Internet (ldap, http, https, ftp)
	 * 
	 * @param cert
	 *            X509Certificate object
	 * @return X509CRL object if available or may be null
	 */
	public static X509CRL downloadCRL(X509Certificate cert) {
		URL crlURL = getCRLDistributionPoint(cert);
		String protocol = crlURL.getProtocol();
		if (protocol.equals("http") || protocol.equals("https")
				|| protocol.equals("ftp")) {

			return downloadCRLFromWeb(crlURL);	
		} else if (protocol.equals("ldap")) {

			return downloadCRLFromLDAP(crlURL);
		} else {

			return null;
		}
	}

	/**
	 * Get CRL distribution from web
	 * 
	 * @param cert
	 * @return
	 */
	private static X509CRL downloadCRLFromWeb(URL crlDistributionPoin) {
		X509CRL crl = null;

		if (crlDistributionPoin == null) {

			return null;
		}

		CertificateFactory cf = null;
		try {
			cf = CertificateFactory.getInstance("X509");
		} catch (CertificateException e) {
			LOG.error("CANNOT INSTANCE CertificateFactory " + e.getMessage());

			return null;
		}

		URLConnection connection;
		try {
			connection = crlDistributionPoin.openConnection();
			connection.setDoInput(true);
			connection.setUseCaches(false);
			DataInputStream inStream = new DataInputStream(
					connection.getInputStream());
			crl = (X509CRL) cf.generateCRL(inStream);
			inStream.close();
		} catch (IOException e) {
			LOG.error("CANNOT GET CRL FROM WEB " + e.getMessage());
		} catch (CRLException e) {
			LOG.error("CANNOT GET CRL FROM WEB " + e.getMessage());
		}

		return crl;
	}

	/**
	 * Get CRL distribution from LDAP
	 * 
	 * @param ldapURL
	 *            LDAP address
	 * @return X509CRL object if available or may be null
	 */
	@SuppressWarnings("rawtypes")
	private static X509CRL downloadCRLFromLDAP(URL ldapURL) {
		X509CRL result = null;
		if (ldapURL == null) {

			return null;
		}

		String ldapURLStr = ldapURL.toString();
		Map<String, String> env = new Hashtable<String, String>();
		env.put(Context.INITIAL_CONTEXT_FACTORY,
				"com.sun.jndi.ldap.LdapCtxFactory");
		env.put(Context.PROVIDER_URL, ldapURLStr);

		DirContext ctx = null;
		try {
			ctx = new InitialDirContext((Hashtable) env);
		} catch (NamingException e) {
			LOG.error("LDAP NAMING EXCEPTION " + e.getMessage());

			return null;
		}

		Attributes avals;
		try {
			avals = ctx.getAttributes("");
			Attribute aval = avals.get("certificateRevocationList;binary");
			byte[] val = (byte[]) aval.get();
			if ((val == null) || (val.length == 0)) {
				return null;
			} else {
				InputStream inStream = new ByteArrayInputStream(val);
				CertificateFactory cf = CertificateFactory.getInstance("X.509");
				result = (X509CRL) cf.generateCRL(inStream);

				try {
					inStream.close();
				} catch (IOException e) {
				}
			}
		} catch (NamingException e) {
			LOG.error("CANNOT GET CRL FROM LDAP " + e.getMessage());
		} catch (CertificateException e) {
			LOG.error("CANNOT GET CRL FROM LDAP " + e.getMessage());
		} catch (CRLException e) {
			LOG.error("CANNOT GET CRL FROM LDAP " + e.getMessage());
		}

		return result;
	}

	/**
	 * Get CRL distribution point from extension value in X509Certificate object
	 * 
	 * @param cert
	 *            X509Certificate object
	 * @return URL of X509CRL distribution point if available or may be null
	 */
	private static URL getCRLDistributionPoint(X509Certificate cert) {
		ASN1Object obj = null;
		try {
			obj = getExtensionValue(cert, Extension.cRLDistributionPoints);
		} catch (IOException e) {
			LOG.error("NO CRL DISTRIBUTION POINT EXTENSION VALUE");
		}
		if (obj == null) {

			return null;
		}
		ASN1Sequence distributionPoints = (ASN1Sequence) obj;
		for (int i = 0; i < distributionPoints.size(); i++) {
			ASN1Sequence distrPoint = (ASN1Sequence) distributionPoints
					.getObjectAt(i);
			for (int j = 0; j < distrPoint.size(); j++) {
				ASN1TaggedObject tagged = (ASN1TaggedObject) distrPoint
						.getObjectAt(j);
				if (tagged.getTagNo() == 0) {
					String url = getStringFromGeneralNames(tagged.getObject());
					if (url != null) {
						try {
							return new URL(url);
						} catch (MalformedURLException e) {

							return null;
						}
					}
				}
			}
		}

		return null;
	}

	/**
	 * Until method to get Extension value from OID
	 * 
	 * @param cert
	 *            X509Certificate object
	 * @param oid
	 *            Extension OID. In this case is CRL distribution point
	 * @return An ASN1Object if available or may be null
	 * @throws IOException
	 */
	protected static ASN1Object getExtensionValue(X509Certificate cert,
			ASN1ObjectIdentifier oid) throws IOException {
		if (cert == null) {
			return null;
		}
		byte[] bytes = cert.getExtensionValue(oid.getId());
		if (bytes == null) {
			return null;
		}
		ASN1InputStream aIn = new ASN1InputStream(
				new ByteArrayInputStream(bytes));
		ASN1OctetString octs = (ASN1OctetString) aIn.readObject();
		aIn = new ASN1InputStream(new ByteArrayInputStream(octs.getOctets()));
		return aIn.readObject();
	} // getExtensionValue

	/**
	 * Copy from some where, don't remember, sory
	 * 
	 * @param names
	 * @return
	 */
	private static String getStringFromGeneralNames(ASN1Object names) {
		ASN1Sequence namesSequence = ASN1Sequence
				.getInstance((ASN1TaggedObject) names, false);
		if (namesSequence.size() == 0) {
			return null;
		}
		DERTaggedObject taggedObject = (DERTaggedObject) namesSequence
				.getObjectAt(0);
		return new String(
				ASN1OctetString.getInstance(taggedObject, false).getOctets());
	}
	
	private static String getRevocationReason(CRLReason reason){
		if(reason.compareTo(CRLReason.AA_COMPROMISE) == 0){
			return "AA_COMPROMISE";
		}
		if(reason.compareTo(CRLReason.AFFILIATION_CHANGED) == 0){
			return "AFFILIATION_CHANGED";
		}
		if(reason.compareTo(CRLReason.CA_COMPROMISE) == 0){
			return "CA_COMPROMISE";
		}
		if(reason.compareTo(CRLReason.CERTIFICATE_HOLD) == 0){
			return "CERTIFICATE_HOLD";
		}
		if(reason.compareTo(CRLReason.CESSATION_OF_OPERATION) == 0){
			return "CESSATION_OF_OPERATION";
		}
		if(reason.compareTo(CRLReason.KEY_COMPROMISE) == 0){
			return "KEY_COMPROMISE";
		}
		if(reason.compareTo(CRLReason.PRIVILEGE_WITHDRAWN) == 0){
			return "PRIVILEGE_WITHDRAWN";
		}
		if(reason.compareTo(CRLReason.REMOVE_FROM_CRL) == 0){
			return "REMOVE_FROM_CRL";
		}
		if(reason.compareTo(CRLReason.SUPERSEDED) == 0){
			return "SUPERSEDED";
		}
		if(reason.compareTo(CRLReason.UNUSED) == 0){
			return "UNUSED";
		}
		if(reason.compareTo(CRLReason.UNSPECIFIED) == 0){
			return "UNSPECIFIED";
		}
		return "UNKNOWN";
	}
}