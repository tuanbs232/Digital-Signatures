package com.bkav.bkavsignature.ooxml;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.openxml4j.opc.Package;
import org.openxml4j.opc.PackageAccess;
import org.openxml4j.opc.signature.PackageDigitalSignatureManager;

import com.bkav.bkavsignature.utils.BkavSignaturesException;
import com.bkav.bkavsignature.utils.CryptoToken;

public class OOXMLSigner {
	/**
	 * Sign office data (docx, pptx, xlsx)
	 * 
	 * @param data
	 *            byte array office data
	 * @param token
	 *            CryptoToken object
	 * @return byte array signed data
	 * @throws BkavSignaturesException
	 */
	public static byte[] sign(byte[] data, CryptoToken token)
			throws BkavSignaturesException {
		if (data == null) {
			throw new BkavSignaturesException("Unsign data null");
		}
		if (token == null) {
			throw new BkavSignaturesException("CryptoToken null");
		}

		// Get and check signer's information
		X509Certificate signerCert = token.getSignerCert();
		if (signerCert == null) {
			throw new BkavSignaturesException("Signer certificate null");
		}
		PrivateKey pk = token.getPrivateKey();
		if (pk == null) {
			throw new BkavSignaturesException("Signer private key null");
		}

		InputStream input = new ByteArrayInputStream(data);
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		Package pkg = null;
		PackageDigitalSignatureManager pkgSigMgr = null;
		try {
			pkg = Package.open(input, PackageAccess.READ_WRITE);
			pkgSigMgr = new PackageDigitalSignatureManager(pkg);
			pkgSigMgr.SignDocument(pk, signerCert);
			pkgSigMgr.getContainer().save(bos);
		} catch (Exception ex) {
			throw new BkavSignaturesException("Cannot create signature", ex);
		} finally {
			if (pkgSigMgr != null) {
				try {
					pkgSigMgr.getContainer().close();
				} catch (IOException e) {
				}
			}
			if (pkg != null) {
				try {
					pkg.close();
				} catch (IOException e) {
				}
			}
		}
		byte[] result = bos.toByteArray();

		if (input != null) {
			try {
				input.close();
			} catch (IOException e) {
			}
		}
		if (bos != null) {
			try {
				bos.close();
			} catch (IOException e) {
			}
		}
		return result;
	}
}
