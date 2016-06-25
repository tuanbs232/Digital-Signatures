package com.bkav.bkavsignature.jar;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.zip.ZipFile;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import sun.misc.BASE64Encoder;
import sun.security.util.ManifestDigester;

/**
 * Worker implement create jar file signature
 * 
 * @author TuanBS (tuanbs@bkav.com)
 *
 */
public class JarSignerImpl extends Object {
	// Default TSA responder
	private String tsaUrl = "http://timestamp.comodoca.com/authenticode";

	private final String signerName;
	private final PrivateKey privKey;
	private final X509Certificate[] certChain;

	/**
	 * Default constructor
	 * 
	 * @param privKey
	 *            Signer's constructor
	 * @param signerCert
	 *            Signer's certificate
	 * @param certchain
	 *            array contain certchain of signer's certificate
	 * @param tsaUrl
	 *            url of timestamp signer
	 */
	public JarSignerImpl(PrivateKey privKey, X509Certificate signerCert,
			X509Certificate[] certchain, String tsaUrl) {
		this.signerName = getSignerName(signerCert);
		this.privKey = privKey;
		this.certChain = certchain;
		this.tsaUrl = tsaUrl;
	}

	/**
	 * Detect Signer's name from subject DN in signer's certificate
	 * 
	 * @param signerCert
	 *            Signer's certificate
	 * @return CN field in subject DN or empty string
	 */
	private String getSignerName(X509Certificate signerCert) {
		try {
			LdapName ldap = new LdapName(signerCert.getSubjectDN().getName());
			List<Rdn> rdns = ldap.getRdns();
			for (Rdn rdn : rdns) {
				if (rdn.getType().equalsIgnoreCase("CN")) {
					return rdn.getValue().toString();
				}
			}
		} catch (InvalidNameException e) {
			return "";
		}

		return "";
	}

	/**
	 * Get Manifest object from jar file
	 * 
	 * @param jarFile
	 * @return
	 * @throws IOException
	 */
	private static Manifest getManifestFile(JarFile jarFile)
			throws IOException {
		JarEntry je = jarFile.getJarEntry("META-INF/MANIFEST.MF");
		if (je != null) {
			Enumeration<JarEntry> entries = jarFile.entries();
			while (entries.hasMoreElements()) {
				je = (JarEntry) entries.nextElement();
				if ("META-INF/MANIFEST.MF".equalsIgnoreCase(je.getName())) {
					break;
				} else {
					je = null;
				}

			}

		}
		// create the manifest object
		Manifest manifest = new Manifest();
		if (je != null) {
			manifest.read(jarFile.getInputStream(je));
		}
		return manifest;

	}

	private static Map<String, Attributes> pruneManifest(Manifest manifest,
			JarFile jarFile) throws IOException {
		Map<String, Attributes> map = manifest.getEntries();
		Iterator<String> elements = map.keySet().iterator();
		while (elements.hasNext()) {
			String element = (String) elements.next();
			if (jarFile.getEntry(element) == null) {
				elements.remove();
			}

		}
		return map;

	}

	private static Map<String, Attributes> createEntries(Manifest manifest,
			JarFile jarFile) throws IOException {
		Map<String, Attributes> entries = null;
		if (manifest.getEntries().size() > 0) {
			entries = pruneManifest(manifest, jarFile);
		} else {
			// if there are no pre-existing entries in the manifest,
			// then we put a few default ones in
			Attributes attributes = manifest.getMainAttributes();
			attributes.putValue(Attributes.Name.MANIFEST_VERSION.toString(),
					"1.0");
			attributes.putValue("Created-By", System.getProperty("java.version")
					+ " (" + System.getProperty("java.vendor") + ")");
			entries = manifest.getEntries();

		}
		return entries;
	}

	private static BASE64Encoder b64Encoder = new BASE64Encoder();

	private static String updateDigest(MessageDigest digest,
			InputStream inputStream) throws IOException {
		byte[] buffer = new byte[2048];
		int read = 0;
		while ((read = inputStream.read(buffer)) > 0) {
			digest.update(buffer, 0, read);
		}
		inputStream.close();

		return b64Encoder.encode(digest.digest());
	}

	private Map<String, Attributes> updateManifestEntries(Manifest manifest,
			JarFile jarFile, MessageDigest messageDigest,
			Map<String, Attributes> entries) throws IOException {
		Enumeration<JarEntry> jarElements = jarFile.entries();
		while (jarElements.hasMoreElements()) {
			JarEntry jarEntry = (JarEntry) jarElements.nextElement();
			if (jarEntry.getName().startsWith("META-INF")) {
				continue;
			} else if (manifest.getAttributes(jarEntry.getName()) != null) {
				Attributes attributes = manifest
						.getAttributes(jarEntry.getName());
				attributes.putValue("SHA1-Digest", updateDigest(messageDigest,
						jarFile.getInputStream(jarEntry)));

			} else if (!jarEntry.isDirectory()) {
				Attributes attributes = new Attributes();
				attributes.putValue("SHA1-Digest", updateDigest(messageDigest,
						jarFile.getInputStream(jarEntry)));
				entries.put(jarEntry.getName(), attributes);

			}

		}
		return entries;
	}

	private byte[] serialiseManifest(Manifest manifest) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		manifest.write(baos);
		baos.flush();
		baos.close();
		return baos.toByteArray();
	}

	private SignatureFile createSignatureFile(Manifest manifest,
			MessageDigest messageDigest) throws IOException {
		ManifestDigester manifestDigester = new ManifestDigester(
				serialiseManifest(manifest));
		return new SignatureFile(new MessageDigest[] { messageDigest },
				manifest, manifestDigester, signerName, true);
	}

	private static void writeJarEntry(JarEntry je, JarFile jarFile,
			JarOutputStream jos) throws IOException {
		jos.putNextEntry(je);
		byte[] buffer = new byte[2048];
		int read = 0;
		InputStream is = jarFile.getInputStream(je);
		while ((read = is.read(buffer)) > 0) {
			jos.write(buffer, 0, read);
		}
		jos.closeEntry();
	}

	/**
	 * Sign jarfile
	 *
	 * @param jarFile
	 * @param outputStream
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 * @throws IOException
	 * @throws CertificateException
	 */
	public void signJarFile(JarFile jarFile, OutputStream outputStream)
			throws NoSuchAlgorithmException, InvalidKeyException,
			SignatureException, IOException, CertificateException {
		Manifest manifest = getManifestFile(jarFile);

		Map<String, Attributes> entries = createEntries(manifest, jarFile);

		MessageDigest messageDigest = MessageDigest.getInstance("SHA1");
		updateManifestEntries(manifest, jarFile, messageDigest, entries);

		SignatureFile signatureFile = createSignatureFile(manifest,
				messageDigest);

		ZipFile zipFile = new ZipFile(jarFile.getName());
		SignatureFile.Block block = signatureFile.generateBlock(privKey, null,
				certChain, false, tsaUrl, null, null, null, zipFile);

		// write out the manifest to the output jar stream
		String manifestFileName = "META-INF/MANIFEST.MF";
		JarOutputStream jos = new JarOutputStream(outputStream);
		JarEntry manifestFile = new JarEntry(manifestFileName);
		jos.putNextEntry(manifestFile);
		jos.closeEntry();

		String signatureFileName = signatureFile.getMetaName();
		JarEntry signatureFileEntry = new JarEntry(signatureFileName);
		jos.putNextEntry(signatureFileEntry);
		signatureFile.write(jos);
		jos.closeEntry();

		String signatureBlockName = block.getMetaName();
		JarEntry signatureBlockEntry = new JarEntry(signatureBlockName);
		jos.putNextEntry(signatureBlockEntry);
		block.write(jos);
		jos.closeEntry();

		Enumeration<JarEntry> metaEntries = jarFile.entries();
		while (metaEntries.hasMoreElements()) {
			JarEntry metaEntry = (JarEntry) metaEntries.nextElement();
			if (metaEntry.getName().startsWith("META-INF")
					&& !(manifestFileName.equalsIgnoreCase(metaEntry.getName())
							|| signatureFileName
									.equalsIgnoreCase(metaEntry.getName())
							|| signatureBlockName
									.equalsIgnoreCase(metaEntry.getName()))) {
				writeJarEntry(metaEntry, jarFile, jos);
			}

		}

		// now write out the rest of the files to the stream
		Enumeration<JarEntry> allEntries = jarFile.entries();
		while (allEntries.hasMoreElements()) {
			JarEntry entry = (JarEntry) allEntries.nextElement();
			if (!entry.getName().startsWith("META-INF")) {
				writeJarEntry(entry, jarFile, jos);
			}

		}

		// finish the stream that we have been writing to
		jos.flush();
		jos.finish();

		// close the JAR file that we have been using
		jarFile.close();
	}

}
