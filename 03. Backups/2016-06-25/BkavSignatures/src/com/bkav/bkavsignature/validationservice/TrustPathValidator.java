package com.bkav.bkavsignature.validationservice;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Security;
import java.security.cert.CRLException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class TrustPathValidator {
	// Logger for this class
	private final static Logger LOG = Logger
			.getLogger(TrustPathValidator.class);

	//Thu muc chua tat ca CRLs tren Windows
	private final static String BKAVCA_CRL_DIR_WIN = "C:/BkavCA/CRLs";
	//Thu muc chua tat ca CRLs tren Linux
	private final static String BKAVCA_CRL_DIR_LINUX = "/BkavCA/CRLs";

	/**
	 * Kiem tra duong dan tin tuong tu signer's certificate den root ca's
	 * certificate
	 * 
	 * @param cert
	 *            signer's certificate
	 * @param certs
	 *            certificate chain up to root CA
	 * @param signingTime
	 *            signing signature be created
	 * @return
	 */
	public static int validate(X509Certificate cert, Certificate[] certs,
			Date signingTime) {
		Security.addProvider(new BouncyCastleProvider());
		if (certs == null) {
			if (isTrustAnchor(cert)) {
				LOG.info("Signer's certificate is trust anchor");

				return 0;
			} else {
				LOG.error("Cannot verify trustpath. certificate chain null");

				return 1;
			}
		}

		List<Certificate> certChain = new ArrayList<Certificate>();
		for (Certificate c : certs) {
			certChain.add(c);
		}

		List<X509Certificate> certChainWithoutRootCert = new ArrayList<X509Certificate>();
		Certificate rootCert = null;
		List<Object> certsAndCRLS = new ArrayList<Object>();

		Iterator<Certificate> cACerts = certChain.iterator();
		Certificate currentCert = cert;
		while (cACerts.hasNext()) {
			currentCert = cACerts.next();
			X509Certificate x509CurrentCert = (X509Certificate) currentCert;

			// Check validity for each issuer's certificate in path
			if (!x509CurrentCert.equals(cert)) {
				try {
					x509CurrentCert.checkValidity(signingTime);
				} catch (CertificateExpiredException e1) {
					LOG.error("CERTIFICATE EXPIRED "
							+ x509CurrentCert.getSubjectDN());

					return 1;
				} catch (CertificateNotYetValidException e1) {
					LOG.error("CERTIFICATE NOT YET VALID "
							+ x509CurrentCert.getSubjectDN());

					return 1;
				}
			}

			// Find root certificate and create chain without root certifcate
			if (rootCert == null && x509CurrentCert.getSubjectX500Principal()
					.equals(x509CurrentCert.getIssuerX500Principal())) {
				rootCert = currentCert;
			} else {
				certChainWithoutRootCert.add(x509CurrentCert);
			}
		}

		CertPath certPath = null;
		CertStore certStore;

		CertificateFactory certFactory;
		CertPathValidator validator = null;
		PKIXParameters params = null;
		try {
			certFactory = CertificateFactory.getInstance("X509", "BC");

			certsAndCRLS.addAll(certChain);
			certsAndCRLS.add(cert);

			// Bo bot doan nay di cho bot nang. kiem tra trustpath se khong kiem
			// tra tinh tranh revoked cua tung chung thu nua
			// List<X509CRL> x509Crls = getCRLs(certChainWithoutRootCert);
			// certsAndCRLS.addAll(x509Crls);

			certStore = CertStore.getInstance("Collection",
					new CollectionCertStoreParameters(certsAndCRLS));

			// CertPath Construction
			certPath = certFactory.generateCertPath(certChainWithoutRootCert);

			// init cerpath validator
			validator = CertPathValidator.getInstance("PKIX", "BC");

			// init params
			TrustAnchor trustAnc = new TrustAnchor((X509Certificate) rootCert,
					null);
			params = new PKIXParameters(Collections.singleton(trustAnc));
			params.addCertStore(certStore);
			params.setDate(signingTime);
			params.setRevocationEnabled(false);

		} catch (Exception e) {
			LOG.error("Exception on preparing parameters for validation", e);

			return 1;
		}

		PKIXCertPathValidatorResult cpv_result;
		try {
			cpv_result = (PKIXCertPathValidatorResult) validator
					.validate(certPath, params);
			String anchor = cpv_result.getTrustAnchor().getTrustedCert()
					.getSubjectDN().getName();
			try {
				LdapName ldap = new LdapName(cpv_result.getTrustAnchor()
						.getTrustedCert().getSubjectDN().getName());
				List<Rdn> rdns = ldap.getRdns();
				for (Rdn rdn : rdns) {
					if (rdn.getType().equalsIgnoreCase("CN")) {
						anchor = rdn.getValue().toString();
					}
				}
			} catch (InvalidNameException e) {
			}

			CertificateValidator.log += "\n\tTRUST PATH: DONE (Anchor: " + anchor + ")";

			return 0;
		} catch (CertPathValidatorException e) {
			LOG.error("CERTIFICATE PATH IS NOT VALID " + e.getMessage());

			return 1;
		} catch (InvalidAlgorithmParameterException e) {
			LOG.error("EXCEPTION WHEN VERIFY " + e.getMessage());

			return 1;
		}
	}

	// TODO: Can chot lai phuong an lay trusted root. tu window-my hay tu thu
	// muc
	private static boolean isTrustAnchor(X509Certificate rootCACert) {
		if (rootCACert.getBasicConstraints() == -1
				|| !rootCACert.getSubjectX500Principal()
						.equals(rootCACert.getIssuerX500Principal())) {
			return false;
		}

		return true;
	}

	/**
	 * Ham nay lay tat ca crl luu o local phuc vu cho viec kiem tra trustpath
	 * 
	 * @return
	 */
	@SuppressWarnings("unused")
	private static List<X509CRL> getCRLs() {
		List<X509CRL> result = new ArrayList<X509CRL>();
		try {
			CertificateFactory certFactory = CertificateFactory
					.getInstance("X509");

			String issuerCertDir = "";
			String osName = System.getProperty("os.name");
			if (osName.contains("Windows")) {
				issuerCertDir = BKAVCA_CRL_DIR_WIN;
			} else if (osName.contains("Linux")) {
				issuerCertDir = BKAVCA_CRL_DIR_LINUX;
			}

			File containFolder = new File(issuerCertDir);

			for (final File fileEntry : containFolder.listFiles()) {
				if (!fileEntry.isDirectory()
						&& fileEntry.getName().endsWith(".crl")) {
					FileInputStream inStream = new FileInputStream(new File(
							issuerCertDir + "/" + fileEntry.getName()));

					X509CRL crl = (X509CRL) certFactory.generateCRL(inStream);
					result.add(crl);
				}
			}

		} catch (CertificateException e) {
			LOG.error("CANNOT INSTANCE CERTIFICATE FACTORY OBJECT.");

			return null;
		} catch (FileNotFoundException e) {
			LOG.error("CRL FILE NOT FOUND.");

			return null;
		} catch (CRLException e) {
			LOG.error("CANNOT GET CRL FROM FILE.");

			return null;
		}

		return result;
	}

	/**
	 * Download CRLs qua internet
	 * 
	 * @param certChain
	 * @return
	 */
	public static List<X509CRL> getCRLs(List<X509Certificate> certChain) {
		List<X509CRL> result = new ArrayList<X509CRL>();
		for (X509Certificate cert : certChain) {
			X509CRL crl = CRLValidator.downloadCRL(cert);
			if (crl != null) {
				result.add(crl);
			}
		}

		return result;
	}
}
