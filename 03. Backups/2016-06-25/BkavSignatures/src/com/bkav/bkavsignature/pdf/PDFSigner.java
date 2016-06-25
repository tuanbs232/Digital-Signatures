package com.bkav.bkavsignature.pdf;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.bkav.bkavsignature.utils.BkavSignaturesException;
import com.bkav.bkavsignature.utils.CryptoToken;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Font;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.BaseFont;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.ExternalSignature;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;
import com.itextpdf.text.pdf.security.PrivateKeySignature;

/**
 * PDFSigner create PDF signature using itext and bouncycastle For SignServer
 * only because it use folder Fonts fixed code
 * 
 * @author TuanBS (tuanbs@bkav.com)
 *
 */
public class PDFSigner {
	private static final Logger LOG = Logger.getLogger(PDFSigner.class);
	private static final String WINDOWS_FONT_DIR = "C:/BkavCA/Fonts/arial.ttf";
	private static final String LINUX_FONT_DIR = "/BkavCA/Fonts/arial.ttf";

	private static String reason = "Personal Document";
	private static String location = "Owner's company";
	
	/**
	 * Add signature to pdf document
	 * 
	 * @param inputData
	 *            signature field added bytes array. If pass original data, will
	 *            not work
	 * @param token CryptoToken object
	 * @param rea String reason for signing
	 * @param loc location of signer
	 * @return
	 * @throws BkavSignaturesException
	 */
	public static byte[] sign(byte[] inputData, CryptoToken token,
			String rea, String loc) throws BkavSignaturesException {
		reason = rea;
		location = loc;
		return sign(inputData, token);
	}

	/**
	 * Add signature to pdf document
	 * 
	 * @param inputData
	 *            signature field added bytes array. If pass original data, will
	 *            not work
	 *
	 * @param pk
	 *            Signer's private key
	 * 
	 * @param certChain
	 *            Signer's certificate chain
	 * 
	 * @return sined data
	 * @throws BkavSignaturesException
	 * 
	 */
	public static byte[] sign(byte[] inputData, CryptoToken token)
			throws BkavSignaturesException {
		byte[] result = null;

		if (inputData == null) {
			LOG.error("BkavSignatureException: " + "Unsign data null");
			throw new BkavSignaturesException("Unsign data null");
		}

		if (token == null) {
			LOG.error("BkavSignatureException: " + "CryptoToken null");
			throw new BkavSignaturesException("CryptoToken null");
		}

		// Use private key provider instead of bouncycastle provider
		Provider provider = token.getPrivateKeyProvider();
		if (provider == null) {
			// May be exception when private not RSAPrivateKey
			provider = new BouncyCastleProvider();
		}
		Security.addProvider(provider);

		// Get and check signer's information
		X509Certificate signerCert = token.getSignerCert();
		if (signerCert == null) {
			LOG.error("BkavSignatureException: " + "Signer certificate null");
			throw new BkavSignaturesException("Signer certificate null");
		}
		PrivateKey pk = token.getPrivateKey();
		if (pk == null) {
			LOG.error("BkavSignatureException: " + "Signer private key null");
			throw new BkavSignaturesException("Signer private key null");
		}
		Certificate[] certChain = new Certificate[1];
		certChain[0] = signerCert;

		// Sign pdf document
		PdfReader reader;
		try {
			reader = new PdfReader(inputData);
		} catch (IOException e1) {
			LOG.error("BkavSignatureException: " + "Cannot load input data");
			throw new BkavSignaturesException("Cannot load input data", e1);
		}

		ByteArrayOutputStream outStream = new ByteArrayOutputStream();
		PdfStamper stamper = null;
		try {
			stamper = PdfStamper.createSignature(reader, outStream, '\0');
		} catch (DocumentException e1) {
			LOG.error("DocumentException: " + e1.getMessage());
			throw new BkavSignaturesException(e1.getMessage(), e1);
		} catch (IOException e1) {
			LOG.error("IOException: " + e1.getMessage());
			throw new BkavSignaturesException(e1.getMessage(), e1);
		}

		// Create signature appearance
		// ---------------------------------------------------------
		PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
		appearance.setVisibleSignature(new Rectangle(420, 40, 570, 85), 1,
				"Signserver-field");
		appearance.setReason(reason);
		appearance.setLocation(location);

		String author = "";
		LdapName ldap;
		try {
			ldap = new LdapName(signerCert.getSubjectDN().getName());
			for (Rdn rdn : ldap.getRdns()) {
				if ("CN".equalsIgnoreCase(rdn.getType())) {
					author = rdn.getValue().toString();
					break;
				}
			}
		} catch (InvalidNameException e) {
		}

		// Show visible signature
		Font fnt = null;
		String fontDir = "";
		if (System.getProperty("os.name").contains("Windows")) {
			fontDir = WINDOWS_FONT_DIR;
		} else {
			fontDir = LINUX_FONT_DIR;
		}
		try {
			BaseFont bf = BaseFont.createFont(fontDir, BaseFont.IDENTITY_H,
					BaseFont.EMBEDDED);
			fnt = new Font(bf, 6);
		} catch (DocumentException e2) {
		} catch (IOException e2) {
		}

		SimpleDateFormat df = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
		String singingTime = df.format(new Date());
		String test = "Ký bởi: " + author + "\nKý ngày: " + singingTime;
		appearance.setLayer2Font(fnt);
		appearance.setLayer2Text(test);
		// ---------------------------------------------------------

		// Generate signature
		// ---------------------------------------------------------
		ExternalSignature es = new PrivateKeySignature(pk, "SHA-1",
				provider.getName());
		ExternalDigest digest = new BouncyCastleDigest();
		try {
			MakeSignature.signDetached(appearance, digest, es, certChain, null,
					null, null, 0, CryptoStandard.CMS);

			result = outStream.toByteArray();

			outStream.close();
		} catch (IOException e) {
			LOG.error("IOException: " + e.getMessage());
			throw new BkavSignaturesException(e.getMessage(), e);
		} catch (DocumentException e) {
			LOG.error("DocumentException: " + e.getMessage());
			throw new BkavSignaturesException(e.getMessage(), e);
		} catch (GeneralSecurityException e) {
			LOG.error("GeneralSecurityException: " + e.getMessage());
			throw new BkavSignaturesException(e.getMessage(), e);
		}
		// ---------------------------------------------------------

		return result;
	}
}
