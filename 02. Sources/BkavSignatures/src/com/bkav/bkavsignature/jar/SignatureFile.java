package com.bkav.bkavsignature.jar;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.Map;
import java.util.jar.Attributes;
import java.util.jar.Manifest;
import java.util.zip.ZipFile;

import sun.misc.BASE64Encoder;
import sun.security.util.ManifestDigester;

public class SignatureFile {
	/** SignatureFile */
	Manifest sf;

	/** .SF base name */
	String baseName;

	public SignatureFile(MessageDigest digests[], Manifest mf,
			ManifestDigester md, String baseName, boolean signManifest)

	{
		this.baseName = baseName;

		String version = System.getProperty("java.version");
		String javaVendor = System.getProperty("java.vendor");

		sf = new Manifest();
		Attributes mattr = sf.getMainAttributes();
		BASE64Encoder encoder = new JarBASE64Encoder();

		mattr.putValue(Attributes.Name.SIGNATURE_VERSION.toString(), "1.0");
		mattr.putValue("Created-By", version + " (" + javaVendor + ")");

		if (signManifest) {
			// sign the whole manifest
			for (int i = 0; i < digests.length; i++) {
				mattr.putValue(digests[i].getAlgorithm() + "-Digest-Manifest",
						encoder.encode(md.manifestDigest(digests[i])));
			}
		}

		// create digest of the manifest main attributes
		ManifestDigester.Entry mde = md.get(ManifestDigester.MF_MAIN_ATTRS,
				false);
		if (mde != null) {
			for (int i = 0; i < digests.length; i++) {
				mattr.putValue(
						digests[i].getAlgorithm() + "-Digest-"
								+ ManifestDigester.MF_MAIN_ATTRS,
						encoder.encode(mde.digest(digests[i])));
			}
		} else {
			throw new IllegalStateException("ManifestDigester failed to create "
					+ "Manifest-Main-Attribute entry");
		}

		/* go through the manifest entries and create the digests */

		Map<String, Attributes> entries = sf.getEntries();
		Iterator<Map.Entry<String, Attributes>> mit = mf.getEntries().entrySet()
				.iterator();
		while (mit.hasNext()) {
			Map.Entry<String, Attributes> e = mit.next();
			String name = e.getKey();
			mde = md.get(name, false);
			if (mde != null) {
				Attributes attr = new Attributes();
				for (int i = 0; i < digests.length; i++) {
					attr.putValue(digests[i].getAlgorithm() + "-Digest",
							encoder.encode(mde.digest(digests[i])));
				}
				entries.put(name, attr);
			}
		}
	}

	/**
	 * Writes the SignatureFile to the specified OutputStream.
	 *
	 * @param out
	 *            the output stream
	 * @exception IOException
	 *                if an I/O error has occurred
	 */

	public void write(OutputStream out) throws IOException {
		sf.write(out);
	}

	/**
	 * get .SF file name
	 */
	public String getMetaName() {
		return "META-INF/" + baseName + ".SF";
	}

	/**
	 * get base file name
	 */
	public String getBaseName() {
		return baseName;
	}

	/*
	 * Generate a signed data block. If a URL or a certificate (containing a
	 * URL) for a Timestamping Authority is supplied then a signature timestamp
	 * is generated and inserted into the signed data block.
	 *
	 * @param sigalg signature algorithm to use, or null to use default
	 * 
	 * @param tsaUrl The location of the Timestamping Authority. If null then no
	 * timestamp is requested.
	 * 
	 * @param tsaCert The certificate for the Timestamping Authority. If null
	 * then no timestamp is requested.
	 * 
	 * @param signingMechanism The signing mechanism to use.
	 * 
	 * @param args The command-line arguments to jarsigner.
	 * 
	 * @param zipFile The original source Zip file.
	 */
	public Block generateBlock(PrivateKey privateKey, String sigalg,
			X509Certificate[] certChain, boolean externalSF, String tsaUrl,
			X509Certificate tsaCert, ContentSigner signingMechanism,
			String[] args, ZipFile zipFile)
			throws NoSuchAlgorithmException, InvalidKeyException, IOException,
			SignatureException, CertificateException {
		return new Block(this, privateKey, sigalg, certChain, externalSF,
				tsaUrl, tsaCert, signingMechanism, args, zipFile);
	}

	public static class Block {

		private byte[] block;
		private String blockFileName;

		/*
		 * Construct a new signature block.
		 */
		Block(SignatureFile sfg, PrivateKey privateKey, String sigalg,
				X509Certificate[] certChain, boolean externalSF, String tsaUrl,
				X509Certificate tsaCert, ContentSigner signingMechanism,
				String[] args, ZipFile zipFile)
				throws NoSuchAlgorithmException, InvalidKeyException,
				IOException, SignatureException, CertificateException {

			String digestAlgorithm;
			String signatureAlgorithm;
			String keyAlgorithm = privateKey.getAlgorithm();
			/*
			 * If no signature algorithm was specified, we choose a default that
			 * is compatible with the private key algorithm.
			 */
			if (sigalg == null) {

				if (keyAlgorithm.equalsIgnoreCase("DSA"))
					digestAlgorithm = "SHA1";
				else if (keyAlgorithm.equalsIgnoreCase("RSA"))
					digestAlgorithm = "SHA1";
				else {
					throw new RuntimeException(
							"private key is not a DSA or " + "RSA key");
				}
				signatureAlgorithm = digestAlgorithm + "with" + keyAlgorithm;
			} else {
				signatureAlgorithm = sigalg;
			}

			// check common invalid key/signature algorithm combinations
			String sigAlgUpperCase = signatureAlgorithm.toUpperCase();
			if ((sigAlgUpperCase.endsWith("WITHRSA")
					&& !keyAlgorithm.equalsIgnoreCase("RSA"))
					|| (sigAlgUpperCase.endsWith("WITHDSA")
							&& !keyAlgorithm.equalsIgnoreCase("DSA"))) {
				throw new SignatureException(
						"private key algorithm is not compatible with signature algorithm");
			}

			blockFileName = "META-INF/" + sfg.getBaseName() + "."
					+ keyAlgorithm;

			Signature sig = Signature.getInstance(signatureAlgorithm);
			sig.initSign(privateKey);

			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			sfg.write(baos);

			byte[] content = baos.toByteArray();

			sig.update(content);
			byte[] signature = sig.sign();

			// Timestamp the signature and generate the signature block file
			if (signingMechanism == null) {
				signingMechanism = new TimestampedSigner();
			}
			URI tsaUri = null;
			try {
				if (tsaUrl != null) {
					tsaUri = new URI(tsaUrl);
				}
			} catch (URISyntaxException e) {
				IOException ioe = new IOException();
				ioe.initCause(e);
				throw ioe;
			}

			// Assemble parameters for the signing mechanism
			ContentSignerParameters params = new JarSignerParameters(args,
					tsaUri, tsaCert, signature, signatureAlgorithm, certChain,
					content, zipFile);

			// Generate the signature block
			block = signingMechanism.generateSignedData(params, externalSF,
					(tsaUrl != null || tsaCert != null));
		}

		/*
		 * get block file name.
		 */
		public String getMetaName() {
			return blockFileName;
		}

		/**
		 * Writes the block file to the specified OutputStream.
		 *
		 * @param out
		 *            the output stream
		 * @exception IOException
		 *                if an I/O error has occurred
		 */

		public void write(OutputStream out) throws IOException {
			out.write(block);
		}
	}
}
