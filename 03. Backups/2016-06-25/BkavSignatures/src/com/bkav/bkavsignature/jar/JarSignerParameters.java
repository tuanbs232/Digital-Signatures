package com.bkav.bkavsignature.jar;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.zip.ZipFile;

class JarSignerParameters implements ContentSignerParameters {

	private String[] args;
	private URI tsa;
	private X509Certificate tsaCertificate;
	private byte[] signature;
	private String signatureAlgorithm;
	private X509Certificate[] signerCertificateChain;
	private byte[] content;
	private ZipFile source;

	/**
	 * Create a new object.
	 */
	JarSignerParameters(String[] args, URI tsa, X509Certificate tsaCertificate,
			byte[] signature, String signatureAlgorithm,
			X509Certificate[] signerCertificateChain, byte[] content,
			ZipFile source) {

		if (signature == null || signatureAlgorithm == null
				|| signerCertificateChain == null) {
			throw new NullPointerException();
		}
		this.args = args;
		this.tsa = tsa;
		this.tsaCertificate = tsaCertificate;
		this.signature = signature;
		this.signatureAlgorithm = signatureAlgorithm;
		this.signerCertificateChain = signerCertificateChain;
		this.content = content;
		this.source = source;
	}

	/**
	 * Retrieves the command-line arguments.
	 *
	 * @return The command-line arguments. May be null.
	 */
	public String[] getCommandLine() {
		return args;
	}

	/**
	 * Retrieves the identifier for a Timestamping Authority (TSA).
	 *
	 * @return The TSA identifier. May be null.
	 */
	public URI getTimestampingAuthority() {
		return tsa;
	}

	/**
	 * Retrieves the certificate for a Timestamping Authority (TSA).
	 *
	 * @return The TSA certificate. May be null.
	 */
	public X509Certificate getTimestampingAuthorityCertificate() {
		return tsaCertificate;
	}

	/**
	 * Retrieves the signature.
	 *
	 * @return The non-null signature bytes.
	 */
	public byte[] getSignature() {
		return signature;
	}

	/**
	 * Retrieves the name of the signature algorithm.
	 *
	 * @return The non-null string name of the signature algorithm.
	 */
	public String getSignatureAlgorithm() {
		return signatureAlgorithm;
	}

	/**
	 * Retrieves the signer's X.509 certificate chain.
	 *
	 * @return The non-null array of X.509 public-key certificates.
	 */
	public X509Certificate[] getSignerCertificateChain() {
		return signerCertificateChain;
	}

	/**
	 * Retrieves the content that was signed.
	 *
	 * @return The content bytes. May be null.
	 */
	public byte[] getContent() {
		return content;
	}

	/**
	 * Retrieves the original source ZIP file before it was signed.
	 *
	 * @return The original ZIP file. May be null.
	 */
	public ZipFile getSource() {
		return source;
	}
}