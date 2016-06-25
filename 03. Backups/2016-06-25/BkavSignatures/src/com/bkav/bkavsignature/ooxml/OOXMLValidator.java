package com.bkav.bkavsignature.ooxml;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

import org.openxml4j.opc.Package;
import org.openxml4j.opc.PackageAccess;
import org.openxml4j.opc.signature.PackageDigitalSignature;
import org.openxml4j.opc.signature.PackageDigitalSignatureManager;
import org.openxml4j.opc.signature.VerifyResult;

import com.bkav.bkavsignature.validationservice.CertificateValidator;
import com.bkav.bkavsignature.validationservice.ValidationError;

/**
 * Verify signature on office document
 * 
 * @author TuanBS (tuanbs@bkav.com)
 *
 */
public class OOXMLValidator {

	/**
	 * Verify Office's signature (docx, pptx, xlsx)
	 * 
	 * @param signedData
	 *            Byte array signed data
	 * @param ocspOrCRL
	 *            Certificate validator OCSP or CRL or Both
	 * @return ValidationError
	 */
	public static int verify(byte[] signedData, int ocspOrCRL) {
		if (signedData == null) {
			return ValidationError.CANNOT_LOAD_SIGNED_DATA;
		}
		// TODO: fix bug when signed docx could not be verified
		InputStream input = new ByteArrayInputStream(signedData);

		Package pkg = null;
		PackageDigitalSignatureManager pkgSigMgr = null;
		try {
			pkg = Package.open(input, PackageAccess.READ);
			pkgSigMgr = new PackageDigitalSignatureManager(pkg);
			VerifyResult verifyResult = pkgSigMgr.VerifySignatures();

			boolean signaturesValid = (verifyResult == VerifyResult.Success);

			if (!signaturesValid) {
				return ValidationError.SIGNATURE_INVALID;
			}

			List<PackageDigitalSignature> list = pkgSigMgr.getSignatures();
			for (PackageDigitalSignature signature : list) {
				X509Certificate signerCert = signature.getSigner();

				String time = signature.getSigningTimeStringValue()
						.replace("T", "").replace("D", "").replace("Z", "");
				SimpleDateFormat df = new SimpleDateFormat(
						"yyyy-MM-dd HH:mm:ss");
				Date signingTime = df.parse(time);

				int certValid = CertificateValidator.verify(signerCert, null,
						signingTime, ocspOrCRL);
				if (certValid != ValidationError.CERTIFICATE_STATUS_GOOD) {
					return certValid;
				} else {
					continue;
				}
			}
		} catch (Exception ex) {
		} finally {
			if (pkgSigMgr != null) {
				pkgSigMgr.getContainer().revert();
			}
			if (pkg != null) {
				pkg.revert();
			}
		}
		return ValidationError.SIGNATURE_VALID;
	}
}
