package com.bkav.bkavsignature.utils;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

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
	private static final String PKCS12_KEYSTORE = "PKCS12";
	private static final String CSP_KEYSTORE = "Windows-MY";

	/**
	 * Initial CryptoToken from smartcard using pkcs11 interface
	 * 
	 * @param configDir
	 *            config.cfg file path
	 * @param pin
	 *            smartcard pin
	 * @return
	 * @throws BkavSignaturesException
	 */
	public static CryptoToken initFromPkcs11(String configDir, String pin)
			throws BkavSignaturesException {
		CryptoToken token = null;
		FileInputStream fis = null;
		try {
			fis = new FileInputStream(configDir);
			Provider provider = null;
			try {
				provider = new sun.security.pkcs11.SunPKCS11(fis);
			} catch (Exception ex) {
				throw new BkavSignaturesException("ProviderException", ex);
			}

			if (Security.getProvider(provider.getName()) == null) {
				Security.addProvider(provider);
			}
			KeyStore keystore = KeyStore.getInstance("PKCS11", provider);
			keystore.load(null, pin.toCharArray());

			Enumeration<String> aliases = keystore.aliases();
			if (aliases == null) {
				throw new BkavSignaturesException(
						"No key alias was found in keystore");
			}
			String alias = null;

			while (aliases.hasMoreElements()) {
				String currentAlias = aliases.nextElement();
				if (keystore.isKeyEntry(currentAlias)) {
					alias = currentAlias;
					break;
				}
			}

			// Throw exception if no key entry was found
			if (alias == null) {
				throw new BkavSignaturesException(
						"No key entry was found in keystore");
			}

			token = getFromKeystore(keystore, alias, pin);
		} catch (FileNotFoundException e) {
			throw new BkavSignaturesException("FileNotFoundException", e);
		} catch (KeyStoreException e) {
			throw new BkavSignaturesException("KeyStoreException", e);
		} catch (NoSuchAlgorithmException e) {
			throw new BkavSignaturesException("NoSuchAlgorithmException", e);
		} catch (CertificateException e) {
			throw new BkavSignaturesException("CertificateException", e);
		} catch (IOException e) {
			throw new BkavSignaturesException("IOException", e);
		} catch (UnrecoverableKeyException e) {
			throw new BkavSignaturesException("UnrecoverableKeyException", e);
		} finally {
			if (fis != null) {
				try {
					fis.close();
				} catch (IOException e) {
					// Do nothing here
				}
			}
		}
		return token;
	}

	/**
	 * 
	 * @param inStream
	 * @param password
	 * @return
	 * @throws BkavSignaturesException
	 */
	public static CryptoToken initFromPkcs12(InputStream inStream,
			String password) throws BkavSignaturesException {
		CryptoToken token = null;

		try {
			KeyStore keystore = KeyStore.getInstance(PKCS12_KEYSTORE);
			keystore.load(inStream, password.toCharArray());

			Enumeration<String> aliases = keystore.aliases();
			if (aliases == null || !aliases.hasMoreElements()) {
				throw new BkavSignaturesException(
						"No key alias was found in keystore");
			}
			String alias = null;

			while (aliases.hasMoreElements()) {
				String currentAlias = aliases.nextElement();
				if (keystore.isKeyEntry(currentAlias)) {
					alias = currentAlias;
					break;
				}
			}
			// Throw exception if key entry not be found.
			if (alias == null) {
				throw new BkavSignaturesException(
						"No key entry was found in keystore");
			}

			token = getFromKeystore(keystore, alias, password);
		} catch (KeyStoreException e) {
			throw new BkavSignaturesException("KeyStoreException", e);
		} catch (CertificateException e) {
			throw new BkavSignaturesException("CertificateException", e);
		} catch (NoSuchAlgorithmException e) {
			throw new BkavSignaturesException("NoSuchAlgorithmException", e);
		} catch (IOException e) {
			throw new BkavSignaturesException("IOException", e);
		} catch (UnrecoverableKeyException e) {
			throw new BkavSignaturesException("UnrecoverableKeyException", e);
		}

		return token;
	}

	/**
	 * Create CryptoToken object from java.security.KeyStore (Pkcs11, Pkcs12,
	 * Windows-MY)
	 * 
	 * @param keystore
	 * @param alias
	 * @param password
	 * @return
	 * @throws UnrecoverableKeyException
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws BkavSignaturesException
	 */
	private static CryptoToken getFromKeystore(KeyStore keystore, String alias,
			String password) throws UnrecoverableKeyException,
			KeyStoreException, NoSuchAlgorithmException, CertificateException,
			BkavSignaturesException {
		if (alias == null) {
			throw new BkavSignaturesException("No alias was found in keystore");
		}

		CryptoToken token = null;
		// Get private key from keystore
		PrivateKey privateKey = (PrivateKey) keystore.getKey(alias,
				password.toCharArray());

		// Get signer's certificate and cast to X509Certificate if able
		// Only work with X509Certificate
		Certificate cert = keystore.getCertificate(alias);
		X509Certificate signerCert = null;
		if (cert != null && cert instanceof X509Certificate) {
			signerCert = (X509Certificate) cert;
		}

		// Get signer's certchain and Issuer's certificate
		// Check issuer's signature on signer's certificate first
		Certificate[] certChain = keystore.getCertificateChain(alias);
		X509Certificate issuerCert = null;
		if (signerCert != null) {
			for (Certificate c : certChain) {
				try {
					if (c != null && c instanceof X509Certificate) {
						signerCert.verify(c.getPublicKey());
						issuerCert = (X509Certificate) c;
						break;
					}
				} catch (InvalidKeyException e) {
					// Do nothing here
				} catch (NoSuchProviderException e) {
					// Do nothing here
				} catch (SignatureException e) {
					// Do nothing here
				}
			}
		}

		Provider privateProvider = keystore.getProvider();

		token = new CryptoToken(privateKey, signerCert, issuerCert, certChain,
				privateProvider);

		return token;
	}

	/**
	 * Create CryptoToken store from Windows Certificate store use CSP
	 * 
	 * @param serial
	 *            Certificate serial number
	 * @return a CryptoToken object store signer certificate, issuer certificate
	 *         and signer private key
	 * @throws BkavSignaturesException
	 * @see CryptoToken
	 */
	public static CryptoToken initFromTokenCSP(String serial)
			throws BkavSignaturesException {
		CryptoToken result = null;

		try {
			SunMSCAPI providerMSCAPI = new SunMSCAPI();
			Security.addProvider(providerMSCAPI);
			KeyStore ks = KeyStore.getInstance(CSP_KEYSTORE);
			ks.load(null, null);

			Enumeration<String> aliases = ks.aliases();
			if (aliases == null) {
				throw new BkavSignaturesException(
						"No key alias was found in keystore");
			}
			String alias = null;

			boolean found = false;
			while (aliases.hasMoreElements()) {
				alias = aliases.nextElement();
				Certificate cert = ks.getCertificate(alias);
				if (cert instanceof X509Certificate) {
					X509Certificate x509Cert = (X509Certificate) cert;
					String certSerial = x509Cert.getSerialNumber().toString(16);
					if (certSerial.equalsIgnoreCase(serial)) {
						found = true;
						result = getFromKeystore(ks, alias, "");
						break;
					}
				}
			}

			if (!found) {
				throw new BkavSignaturesException(
						"No entry with this serial was found");
			}
		} catch (KeyStoreException e) {
			throw new BkavSignaturesException("KeyStoreException", e);
		} catch (NoSuchAlgorithmException e) {
			throw new BkavSignaturesException("NoSuchAlgorithmException", e);
		} catch (CertificateException e) {
			throw new BkavSignaturesException("CertificateException", e);
		} catch (IOException e) {
			throw new BkavSignaturesException("IOException", e);
		} catch (UnrecoverableKeyException e) {
			throw new BkavSignaturesException("UnrecoverableKeyException", e);
		} catch (BkavSignaturesException e) {
			throw new BkavSignaturesException("BkavSignaturesException", e);
		}

		return result;
	}

	/**
	 * List all cert in Windows-My
	 * 
	 * @return
	 * @throws BkavSignaturesException
	 */
	public static Map<String, String> listTokenFromCSP()
			throws BkavSignaturesException {
		Map<String, String> result = new HashMap<>();
		try {
			SunMSCAPI providerMSCAPI = new SunMSCAPI();
			Security.addProvider(providerMSCAPI);
			KeyStore ks = KeyStore.getInstance(CSP_KEYSTORE);
			ks.load(null, null);

			Enumeration<String> aliases = ks.aliases();
			String alias = null;

			while (aliases.hasMoreElements()) {
				alias = aliases.nextElement();
				Certificate cert = ks.getCertificate(alias);
				if (cert instanceof X509Certificate) {
					X509Certificate x509Cert = (X509Certificate) cert;
					String certSerial = x509Cert.getSerialNumber().toString(16);

					String subjectDN = x509Cert.getSubjectDN().getName();
					String author = "";
					LdapName ldap;
					try {
						ldap = new LdapName(subjectDN);
						for (Rdn rdn : ldap.getRdns()) {
							if ("CN".equalsIgnoreCase(rdn.getType())) {
								author = rdn.getValue().toString();
								break;
							}
						}
					} catch (InvalidNameException e) {
					}

					result.put(certSerial, author);
				}
			}
		} catch (KeyStoreException e) {
			throw new BkavSignaturesException("KeyStoreException", e);
		} catch (NoSuchAlgorithmException e) {
			throw new BkavSignaturesException("NoSuchAlgorithmException", e);
		} catch (CertificateException e) {
			throw new BkavSignaturesException("CertificateException", e);
		} catch (IOException e) {
			throw new BkavSignaturesException("IOException", e);
		}

		return result;
	}
}
