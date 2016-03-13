package com.bkav.bkavsignature.pdf;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
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

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.bkav.bkavsignature.utils.CryptoToken;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Font;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfAnnotation;
import com.itextpdf.text.pdf.PdfFormField;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.PdfString;
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.ExternalSignature;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;
import com.itextpdf.text.pdf.security.PrivateKeySignature;

public class PDFSigner {

	/**
	 * Create a signature field on original document
	 * 
	 * @param originalData
	 *            bytes array of original document
	 * @return signature field added bytes array
	 */
	private static byte[] createSignatureField(byte[] originalData) {
		byte[] result = null;
		PdfReader pdf;
		try {
			pdf = new PdfReader(originalData);
			ByteArrayOutputStream outStream = new ByteArrayOutputStream();
			PdfStamper stp = new PdfStamper(pdf, outStream);
			PdfFormField sig = PdfFormField.createSignature(stp.getWriter());
			sig.setWidget(new Rectangle(100, 100, 200, 200), null);
			sig.setFlags(PdfAnnotation.FLAGS_PRINT);
			sig.put(PdfName.DA, new PdfString("/Helv 0 Tf 0 g"));
			sig.setFieldName("Signature");
			sig.setPage(1);
			stp.addAnnotation(sig, 1);
			try {
				stp.close();
			} catch (Exception e) {
				e.printStackTrace();
			}

			result = outStream.toByteArray();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (DocumentException e) {
			e.printStackTrace();
		}

		return result;
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
	 * 
	 */
	public static byte[] sign(byte[] inputData, CryptoToken token) {
		byte[] result = null;
		Provider provider = new BouncyCastleProvider();
		Security.addProvider(provider);

		// Get signer's information
		X509Certificate signerCert = token.getCertificate();
		PrivateKey pk = token.getPrivateKey();
//		Certificate[] certChain = token.getCertChain();
		Certificate[] certChain = new Certificate[1];
		certChain[0] = token.getCertificate();

		byte[] signatureFieldAdded = createSignatureField(inputData);

		PdfReader reader;
		try {
			reader = new PdfReader(signatureFieldAdded);
		} catch (IOException e1) {
			e1.printStackTrace();

			return null;
		}

		ByteArrayOutputStream outStream = new ByteArrayOutputStream();
		PdfStamper stamper = null;
		try {
			stamper = PdfStamper.createSignature(reader, outStream, '\0');
		} catch (DocumentException e1) {
			e1.printStackTrace();

			return null;
		} catch (IOException e1) {
			e1.printStackTrace();

			return null;
		}

		// Create signature appearance
		// ---------------------------------------------------------
		PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
		appearance.setVisibleSignature("Signature");
		appearance.setReason("It's personal.");
		appearance.setLocation("Foobar");

		appearance.setVisibleSignature("Signature");

		Font font = new Font();
		font.setFamily("Courier new");
		font.setSize(6);
		font.setStyle(Font.NORMAL);
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
		SimpleDateFormat df = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
		String singingTime = df.format(new Date());
		try {
			byte[] name = ("Ký bởi: " + author + "\nKý ngày: "
					+ singingTime).getBytes();
			author = new String(name, "UTF-8");
		} catch (UnsupportedEncodingException e1) {
			e1.printStackTrace();
		}
		appearance.setLayer2Text(author + appearance.getReason());
		appearance.setLayer2Font(font);
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
			e.printStackTrace();
		} catch (DocumentException e) {
			e.printStackTrace();
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
		// ---------------------------------------------------------

		return result;
	}
}
