package com.bkav.bkavsignature.codesigning;

import java.io.File;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Date;

import org.apache.log4j.Logger;

import com.bkav.bkavsignature.utils.BkavSignaturesException;
import com.bkav.bkavsignature.utils.CommonUtils;
import com.bkav.bkavsignature.utils.CryptoToken;
import com.bkav.bkavsignature.utils.FileUtil;

import net.jsign.PESigner;
import net.jsign.pe.PEFile;

public class ExeSigner {
	private static final Logger LOG = Logger.getLogger(ExeSigner.class);

	private static final String TMP_DIR_WIN = "C:\\BkavCA\\tmp\\";
	private static final String TMP_DIR_LINUX = "/BkavCA/tmp/";
	public static final String TSA_URL = "http://timestamp.comodoca.com/authenticode";

	/**
	 * Sign Microsoft file type
	 * 
	 * @param unsignData
	 *            bytes array unsign data
	 * @param token
	 *            CryptoToken object contain private key, certs, ...
	 * @param tsaUrl
	 *            TSA signer url
	 * @return bytes array signed data or may be exception
	 * @throws BkavSignaturesException
	 */
	public static byte[] sign(byte[] unsignData, CryptoToken token,
			String tsaUrl) throws BkavSignaturesException {
		byte[] signed = null;
		if (unsignData == null) {
			LOG.error("Unsign data null");
			throw new BkavSignaturesException("Unsign data null");
		}
		if (token == null) {
			LOG.error("CryptoToken null");
			throw new BkavSignaturesException("CryptoToken null");
		}

		Certificate[] certChain = token.getCertChain();
		if (certChain == null) {
			LOG.error("No certchain found in CryptoToken");
			throw new BkavSignaturesException(
					"No certchain found in CryptoToken");
		}
		PrivateKey privateKey = token.getPrivateKey();
		if (privateKey == null) {
			LOG.error("No private key found in CryptoToken");
			throw new BkavSignaturesException(
					"No private key found in CryptoToken");
		}

		if (tsaUrl == null) {
			tsaUrl = TSA_URL;
		}

		// Write temp file to create ExcFile
		String osName = System.getProperty("os.name");
		String tmpDirName;
		if (osName.contains("Windows")) {
			tmpDirName = TMP_DIR_WIN;
		} else {
			tmpDirName = TMP_DIR_LINUX;
		}

		File tmpDir = new File(tmpDirName);
		if (!tmpDir.exists()) {
			boolean mkdir = tmpDir.mkdirs();
			if (!mkdir) {
				throw new BkavSignaturesException(
						"ExeSigner.sign()[81]: Cannot create temporary file");
			}
		}

		Date d = new Date();
		String tmpFileName = tmpDirName + "tmp-" + d.getTime() + ".signserver";
		int result = FileUtil.writeToFile(unsignData, tmpFileName);
		if (result != 0) {
			throw new BkavSignaturesException("Cannot create tmp file");
		}

		File file = new File(tmpFileName);

		PEFile peFile;
		try {
			peFile = new PEFile(file);

			PESigner signer = new PESigner(certChain, privateKey);
			signer.withProgramName("signed");

			boolean checkTSA = !(CommonUtils.getAccessError(tsaUrl, true,
					10000) != null);
			signer.withTimestamping(checkTSA);
			signer.withTimestampingAutority(tsaUrl);

			signer.sign(peFile);

			signed = FileUtil.readBytesFromFile(tmpFileName);
		} catch (IOException e) {
			throw new BkavSignaturesException("IOException", e);
		} catch (Exception e) {
			throw new BkavSignaturesException("Exception", e);
		} finally {
			file.deleteOnExit();
		}
		return signed;
	}
}
