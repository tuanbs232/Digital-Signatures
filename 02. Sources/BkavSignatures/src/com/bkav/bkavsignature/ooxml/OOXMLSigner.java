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

import com.bkav.bkavsignature.utils.CryptoToken;
import com.bkav.bkavsignature.utils.CryptoTokenUtil;
import com.bkav.bkavsignature.utils.FileUtil;

public class OOXMLSigner {
	private static final String KEYSTOREPATH = "S:/WORK/2016/01-2016/BCSE_Client.p12";
	private static final String KEYSTOREPASS = "12345678";

	public static void main(String[] args) {
		String filePath = "S:/WORK/2016/01-2016/input.pptx";
		String signedPath = "C:\\Users\\BuiSi\\Desktop\\signed.pptx";
		try {
			byte[] data = FileUtil.readBytesFromFile(filePath);
			byte[] signed = sign(data);
			FileUtil.writeToFile(signed, signedPath);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public static byte[] sign(byte[] data) {
		CryptoToken token = CryptoTokenUtil.initFromPKCS12(KEYSTOREPATH, KEYSTOREPASS);

		PrivateKey privKey = token.getPrivateKey();
		X509Certificate signerCert = token.getCertificate();

		InputStream input = new ByteArrayInputStream(data);
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		Package pkg = null;
		PackageDigitalSignatureManager pkgSigMgr = null;
		try {
			pkg = Package.open(input, PackageAccess.READ_WRITE);
			pkgSigMgr = new PackageDigitalSignatureManager(pkg);
			pkgSigMgr.SignDocument(privKey, signerCert);
			pkgSigMgr.getContainer().save(bos);
		} catch (Exception ex) {
			ex.printStackTrace();
		} finally {
			if (pkgSigMgr != null) {
				try {
					pkgSigMgr.getContainer().close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
			if (pkg != null) {
				try {
					pkg.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
		byte[] result = bos.toByteArray();

		if (input != null) {
			try {
				input.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		if (bos != null) {
			try {
				bos.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return result;
	}
}
