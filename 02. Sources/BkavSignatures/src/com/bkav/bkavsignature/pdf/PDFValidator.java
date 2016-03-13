package com.bkav.bkavsignature.pdf;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;

import org.apache.log4j.Logger;

import com.bkav.bkavsignature.validationservice.CertificateValidator;
import com.bkav.bkavsignature.validationservice.ValidationError;
import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.security.PdfPKCS7;

public class PDFValidator {
	// Logger for this class
	final static Logger LOG = Logger.getLogger(PDFValidator.class);

	/**
	 * Verify pdf signed data
	 * 
	 * @param signedData
	 *            byte array signed data
	 * @return
	 */
	public static int verify(byte[] signedData, int ocspOrCRL) {
		PdfReader reader = null;
		try {
			reader = new PdfReader(signedData);
		} catch (IOException e) {
			LOG.error("CANNOT LOAD SIGNED DATA. " + e.getMessage());

			return ValidationError.CANNOT_LOAD_SIGNED_DATA;
		}

		AcroFields fields = reader.getAcroFields();
		ArrayList<String> names = fields.getSignatureNames();

		if (names == null || names.size() == 0) {
			LOG.error("SIGNATURE NOT FOUND");

			return ValidationError.SIGNATURE_NOT_FOUND;
		}

		for (String name : names) {
			LOG.info(name);
			PdfPKCS7 pkcs7 = fields.verifySignature(name);

			boolean signatureValid = false;
			try {
				signatureValid = pkcs7.verify();
			} catch (GeneralSecurityException e) {
				LOG.error("Signature with field name " + name + " is invalid");
			}

			if (!signatureValid) {
				LOG.error("SIGNATURE INVALID");

				return ValidationError.SIGNATURE_INVALID;
			}

			Date signingTime = pkcs7.getSignDate().getTime();
			X509Certificate signCert = pkcs7.getSigningCertificate();
			Certificate[] certChain = pkcs7.getSignCertificateChain();

			// Verify signer's certificate
			int certValid = CertificateValidator.verify(signCert, certChain,
					signingTime, ocspOrCRL);

			return certValid;
		}

		return ValidationError.SIGNATURE_VALID;
	}
}
