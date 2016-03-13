package com.bkav.bkavsignature.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import sun.security.mscapi.SunMSCAPI;

/**
 * Util class. init CryptoToken object from PKCS12, PKCS11, CSP, ...
 * 
 * @author BuiSi
 *
 */
public class CryptoTokenUtil {

	/**
	 * Get CryptoToken from P12 keystore file
	 * 
	 * @param keystorePath
	 *            Keystore file directory
	 * @param keystorePass
	 *            Keystore file password
	 * @return a CryptoToken object store signer certificate, issuer certificate
	 *         and signer private key
	 * @see CryptoToken
	 */
	public static CryptoToken initFromPKCS12(String keystorePath,
			String keystorePass) {
		CryptoToken result = null;

		// Get PKCS12 keystore instance
		KeyStore ks = null;
		try {
			ks = KeyStore.getInstance("PKCS12", "BC");
		} catch (KeyStoreException e) {
			e.printStackTrace();   //printStackTrace: in ngoai le phat sinh ra man hinh

			return null;
		} catch (NoSuchProviderException e) {    //NoSuchProviderException: Ko co ngoai le nhu cung cap
			e.printStackTrace();
		}

		// Get keystore file to input stream
		InputStream inStream = null;
		try {
			inStream = new FileInputStream(new File(keystorePath)); 
		} catch (FileNotFoundException e) {
			e.printStackTrace();

			return null;
		}

		if (inStream != null) {
			try {
				ks.load(inStream, keystorePass.toCharArray());
				Enumeration<String> aliases = ks.aliases();
				String alias = null;

				while (aliases.hasMoreElements()) {
					alias = aliases.nextElement();

					// Get signer certificate from keystore
					Certificate signerCert = ks.getCertificate(alias);
					X509Certificate signerX509Cert = null;
					if (signerCert instanceof X509Certificate) {
						signerX509Cert = (X509Certificate) signerCert;
					}

					// Get issuer certificate from keystore when signer
					// certificate not null
					X509Certificate issuerX509Cert = null;
					Certificate[] certs = ks.getCertificateChain(alias);
					if (signerX509Cert != null && certs != null) {
						for (Certificate cert : certs) {
							if (cert instanceof X509Certificate) {
								X509Certificate x509Cert = (X509Certificate) cert;
								if (x509Cert.getSubjectDN()
										.equals(signerX509Cert.getIssuerDN())) {
									issuerX509Cert = x509Cert;
									break;
								}
							}
						}
					}

					// Get signer private from keystore
					PrivateKey privKey = (PrivateKey) ks.getKey(alias,
							keystorePass.toCharArray());

					result = new CryptoToken(signerX509Cert, issuerX509Cert,
							certs, privKey);
				}
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch (CertificateException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			} catch (KeyStoreException e) {
				e.printStackTrace();
			} catch (UnrecoverableKeyException e) {
				e.printStackTrace();
			} finally {
				if (inStream != null) {
					try {
						inStream.close();
					} catch (IOException e) {
						e.printStackTrace();
					}
				}
			}
		}

		return result;
	}

	/**
	 * Create CryptoToken store from Windows Certificate store use CSP
	 * 
	 * @param serial
	 *            Certificate serial number
	 * @return a CryptoToken object store signer certificate, issuer certificate
	 *         and signer private key
	 * @see CryptoToken
	 */
	public static CryptoToken initFromTokenCSP(String serial) {
		CryptoToken result = null;

		try {
			SunMSCAPI providerMSCAPI = new SunMSCAPI();
			Security.addProvider(providerMSCAPI);
			KeyStore ks = KeyStore.getInstance("Windows-MY");
			ks.load(null, null);

			Enumeration<String> aliases = ks.aliases();
			String alias = null;

			while (aliases.hasMoreElements()) {
				alias = aliases.nextElement();
				Certificate cert = ks.getCertificate(alias);
				if (cert instanceof X509Certificate) {
					X509Certificate x509Cert = (X509Certificate) cert;
					String certSerial = x509Cert.getSerialNumber().toString(16);

					if (certSerial.equalsIgnoreCase(serial)) {
						// Get private from keystore
						PrivateKey privKey = (PrivateKey) ks.getKey(alias,
								"12345678".toCharArray());

						// Get issuer certificate in certchain
						X509Certificate issuerCert = null;
						Certificate[] certChain = ks.getCertificateChain(alias);
						for (Certificate c : certChain) {
							if (c instanceof X509Certificate) {
								X509Certificate x509C = (X509Certificate) c;
								if (x509C.getSubjectDN()
										.equals(x509Cert.getIssuerDN())) {
									issuerCert = x509C;
								}
							}
						}
						// Create CertificateInfo object contain all information
						// in keystore
						result = new CryptoToken(x509Cert, issuerCert,
								certChain, privKey);
					}

				}
			}
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (UnrecoverableKeyException e) {
			e.printStackTrace();
		}

		return result;
	}

	/**
	 * Get all cert from windows certificate store (folder personal Window-MY)
	 * 
	 * @return
	 */
	public static List<String> getTokenList() {
		List<String> result = new ArrayList<String>();
		try {
			SunMSCAPI providerMSCAPI = new SunMSCAPI();
			Security.addProvider(providerMSCAPI);
			KeyStore ks = KeyStore.getInstance("Windows-MY");
			ks.load(null, null);

			Enumeration<String> aliases = ks.aliases();
			String alias = null;

			while (aliases.hasMoreElements()) {
				alias = aliases.nextElement();
				Certificate cert = ks.getCertificate(alias);
				if (cert instanceof X509Certificate) {
					X509Certificate x509Cert = (X509Certificate) cert;
					String serial = x509Cert.getSerialNumber().toString(16);

					String subjectName = "";
					LdapName ldap;
					try {
						ldap = new LdapName(x509Cert.getSubjectDN().toString());
						for (Rdn rdn : ldap.getRdns()) {
							if ("CN".equalsIgnoreCase(rdn.getType())) {
								subjectName = rdn.getValue().toString();
								break;
							}
						}
					} catch (InvalidNameException e) {
					}

					String tokenName = serial + " - " + subjectName;
					result.add(tokenName);
				}
			}
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return result;
	}

	/**
	 * Load certificate and private key with serial number
	 * 
	 * @param serial
	 *            Serial number of token
	 * @return
	 * @see com.bkav.tokentest.CertificateInfo CertificateInfo
	 */
	public static CryptoToken getTokenInfo(String serial) {
		CryptoToken result = null;

		try {
			SunMSCAPI providerMSCAPI = new SunMSCAPI();
			Security.addProvider(providerMSCAPI);
			KeyStore ks = KeyStore.getInstance("Windows-MY");
			ks.load(null, null);

			Enumeration<String> aliases = ks.aliases();
			String alias = null;

			while (aliases.hasMoreElements()) {
				alias = aliases.nextElement();
				Certificate cert = ks.getCertificate(alias);
				if (cert instanceof X509Certificate) {
					X509Certificate x509Cert = (X509Certificate) cert;
					String certSerial = x509Cert.getSerialNumber().toString(16);

					if (certSerial.equalsIgnoreCase(serial)) {
						// Get private from keystore
						PrivateKey privKey = (PrivateKey) ks.getKey(alias,
								null);

						// Get issuer certificate in certchain
						X509Certificate issuerCert = null;
						Certificate[] certChain = ks.getCertificateChain(alias);
						for (Certificate c : certChain) {
							if (c instanceof X509Certificate) {
								X509Certificate x509C = (X509Certificate) c;
								if (x509C.getSubjectDN()
										.equals(x509Cert.getIssuerDN())) {
									issuerCert = x509C;
								}
							}
						}
						// Create CertificateInfo object contain all information
						// in keystore
						result = new CryptoToken(x509Cert, issuerCert, privKey);
					}

				}
			}
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (UnrecoverableKeyException e) {
			e.printStackTrace();
		}

		return result;
	}

}
