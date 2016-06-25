/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.bkav.bkavsignature.jar;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.jar.JarFile;

import org.apache.log4j.Logger;

import com.bkav.bkavsignature.utils.BkavSignaturesException;
import com.bkav.bkavsignature.utils.CommonUtils;
import com.bkav.bkavsignature.utils.CryptoToken;
import com.bkav.bkavsignature.utils.FileUtil;

/**
 * Create signature signature for jar file Hack from jarsigner class in openjdk
 * 
 * @author TUANBS
 */
public class JarSigner {
	private static final Logger LOG = Logger.getLogger(JarSigner.class);

	// Temp directory to store temp file from unsign data before create
	// signature on this temp file
	private static final String TMP_DIR_WIN = "C:\\BkavCA\\tmp\\";
	private static final String TMP_DIR_LINUX = "/BkavCA/tmp/";

	/**
	 * Ham thuc hien ky du lieu
	 *
	 * @param data
	 *            byte array jar file data
	 * @param tsaUrl
	 *            TSA responder url
	 * @return byte array or may be null
	 * @throws BkavSignaturesException
	 */
	public static byte[] sign(byte[] data, CryptoToken token, String tsaUrl)
			throws BkavSignaturesException {
		if (data == null) {
			throw new BkavSignaturesException("Unsign data null");
		}
		if (token == null) {
			throw new BkavSignaturesException("Crypto Token null");
		}
		Certificate[] certChain = token.getCertChain();
		if (certChain == null) {
			throw new BkavSignaturesException(
					"No certchain found in cryptotoken");
		}
		List<X509Certificate> certList = new ArrayList<>();
		for (Certificate c : certChain) {
			if (c instanceof X509Certificate) {
				certList.add((X509Certificate) c);
			}
		}
		X509Certificate[] certchain = new X509Certificate[certList.size()];
		for (int i = 0; i < certchain.length; i++) {
			certchain[i] = certList.get(i);
		}

		PrivateKey privKey = token.getPrivateKey();
		if (privKey == null) {
			throw new BkavSignaturesException(
					"No private key found in CryptoToken");
		}

		X509Certificate cert = token.getSignerCert();

		// Check tsa url and set to signer
		boolean useTsa = false;
		if (tsaUrl != null && !"".equals(tsaUrl)) {
			useTsa = !(CommonUtils.getAccessError(tsaUrl, true, 10000) != null);
		} else {
			LOG.warn("TSA_URL not set");
		}
		if (!useTsa) {
			tsaUrl = null;
		}

		JarSignerImpl jarSigner = new JarSignerImpl(privKey,
				(X509Certificate) cert, certchain, tsaUrl);

		// Write temp file to create JarFile
		String osName = System.getProperty("os.name");
		String tmpDirName;
		if (osName.contains("Windows")) {
			tmpDirName = TMP_DIR_WIN;
		} else {
			tmpDirName = TMP_DIR_LINUX;
		}
		File tmpDir = new File(tmpDirName);
		if (!tmpDir.exists()) {
			tmpDir.mkdirs();
		}
		Date d = new Date();
		String tmpFileName = tmpDirName + "tmp-" + d.getTime() + ".jar";
		int returnCode = FileUtil.writeToFile(data, tmpFileName);
		if (returnCode != 0) {
			throw new BkavSignaturesException(
					"Cannot create temp file to create signature");
		}
		File file = new File(tmpFileName);

		ByteArrayOutputStream outStream = new ByteArrayOutputStream();

		JarFile jarFile = null;
		try {
			jarFile = new JarFile(file);
		} catch (IOException e) {
			throw new BkavSignaturesException(
					"Cannot create jar file from unsign data");
		}

		// Create signature
		try {
			jarSigner.signJarFile(jarFile, outStream);
		} catch (NoSuchAlgorithmException ex) {
			throw new BkavSignaturesException("NoSuchAlgorithmException", ex);
		} catch (InvalidKeyException ex) {
			throw new BkavSignaturesException("InvalidKeyException", ex);
		} catch (SignatureException ex) {
			throw new BkavSignaturesException("SignatureException", ex);
		} catch (IOException ex) {
			throw new BkavSignaturesException("IOException", ex);
		} catch (CertificateException ex) {
			throw new BkavSignaturesException("CertificateException", ex);
		} finally {
			file.deleteOnExit();
		}

		byte[] result = outStream.toByteArray();
		try {
			outStream.close();
			jarFile.close();
			file.deleteOnExit();
		} catch (IOException ex) {
			throw new BkavSignaturesException(
					"IOException - Cannot write to output stream", ex);
		}

		return result;
	}
}
