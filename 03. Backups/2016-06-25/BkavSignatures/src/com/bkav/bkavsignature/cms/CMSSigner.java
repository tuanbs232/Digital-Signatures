package com.bkav.bkavsignature.cms;

import java.io.IOException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import com.bkav.bkavsignature.utils.BkavSignaturesException;
import com.bkav.bkavsignature.utils.CryptoToken;

public class CMSSigner {
	/**
	 * Create PKCS#7 ctypto message
	 * 
	 * @param inputData
	 *            byte array input data
	 * @param token
	 *            CryptoToken object
	 * @param detached
	 *            true if contain data false if not
	 * @return signed byte array or null
	 * @throws BkavSignaturesException
	 */
	public byte[] sign(byte[] inputData, CryptoToken token, boolean detached)
			throws BkavSignaturesException {
		Security.addProvider(token.getPrivateKeyProvider());
		byte[] signedbytes = null;
		X509Certificate signerCert = token.getSignerCert();
		if (signerCert == null || signerCert.getPublicKey() == null) {
			throw new BkavSignaturesException("No signer certificate was found.");
		}

		Certificate[] certChain = token.getCertChain();
		if (certChain == null) {
			throw new BkavSignaturesException("No certchain was found.");
		}
		// Generate CMS Signer and create signature
		final CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
		final String signAlg = getDefaultSignatureAlgorithm(
				token.getSignerCert().getPublicKey());

		ContentSigner contentSigner;
		try {
			contentSigner = new JcaContentSignerBuilder(signAlg)
					.setProvider(token.getPrivateKeyProvider())
					.build(token.getPrivateKey());

			generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
					new JcaDigestCalculatorProviderBuilder()
							.setProvider(new BouncyCastleProvider()).build())
									.build(contentSigner, signerCert));

			generator.addCertificates(
					new JcaCertStore(getIncludeCert(certChain)));

			final CMSTypedData content = new CMSProcessableByteArray(inputData);

			// Co du lieu
			final CMSSignedData signedData = generator.generate(content,
					detached);

			signedbytes = signedData.getEncoded();

		} catch (OperatorCreationException e) {
			throw new BkavSignaturesException("Cannot generate CMS signer.", e);
		} catch (CertificateEncodingException e) {
			throw new BkavSignaturesException("Cannot generate CMS signer.", e);
		} catch (CMSException e) {
			throw new BkavSignaturesException("Cannot generate CMS signer.", e);
		} catch (IOException e) {
			throw new BkavSignaturesException("Cannot generate CMS signature.",
					e);
		}

		return signedbytes;
	}

	/**
	 * Get Signature Algorithm from public key
	 * 
	 * @param publicKey
	 *            Crypto token's public key
	 * @return String name of algorithm
	 */
	private String getDefaultSignatureAlgorithm(final PublicKey publicKey) {
		final String result;

		if (publicKey instanceof ECPublicKey) {
			result = "SHA1withECDSA";
		} else if (publicKey instanceof DSAPublicKey) {
			result = "SHA1withDSA";
		} else {
			result = "SHA1withRSA";
		}

		return result;
	}

	/**
	 * Convert certificate chain from token to list
	 * 
	 * @param chain
	 *            certChain from CryptoToken
	 * @return List Certificate
	 */
	private List<Certificate> getIncludeCert(Certificate[] chain) {
		List<Certificate> result = new ArrayList<>();
		for (Certificate c : chain) {
			result.add(c);
		}

		return result;
	}
}
