package com.bkav.bkavsignature.utils;

import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

/**
 * Doi tuong luu thong tin co ban ve ca phan public (Certificate, public key) va
 * phan private (private key).
 * 
 * @author BuiSi
 *
 */
public class CryptoToken {
	private X509Certificate certificate;
	private X509Certificate issuerCertificate;
	private Certificate[] certChain;
	private PrivateKey privateKey;

	/**
	 * Default constructor
	 */
	public CryptoToken() {
	}

	/**
	 * 
	 * @param certificate
	 *            X509Certificate object
	 * @param privateKey
	 *            Private key match certificate
	 */
	public CryptoToken(X509Certificate certificate,
			X509Certificate issuerCert, PrivateKey privateKey) {
		this.setCertificate(certificate);
		this.issuerCertificate = issuerCert;
		this.setPrivateKey(privateKey);
	}

	public CryptoToken(X509Certificate certificate,
			X509Certificate issuerCert, Certificate[] certs,
			PrivateKey privateKey) {
		this.setCertificate(certificate);
		this.issuerCertificate = issuerCert;
		this.setCertChain(certs);
		this.setPrivateKey(privateKey);
	}

	public X509Certificate getCertificate() {
		return certificate;
	}

	public void setCertificate(X509Certificate certificate) {
		this.certificate = certificate;
	}

	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	public void setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}

	public X509Certificate getIssuerCertificate() {
		return issuerCertificate;
	}

	public void setIssuerCertificate(X509Certificate issuerCertificate) {
		this.issuerCertificate = issuerCertificate;
	}

	public Certificate[] getCertChain() {
		return certChain;
	}

	public void setCertChain(Certificate[] certChain) {
		this.certChain = certChain;
	}

}