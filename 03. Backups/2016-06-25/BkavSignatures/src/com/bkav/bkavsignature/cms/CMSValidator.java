package com.bkav.bkavsignature.cms;

import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

import org.apache.log4j.Logger;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;

import com.bkav.bkavsignature.utils.BkavSignaturesException;
import com.bkav.bkavsignature.validationservice.CertificateValidator;
import com.bkav.bkavsignature.validationservice.ValidationError;

public class CMSValidator {
	private static final Logger LOG = Logger.getLogger(CMSValidator.class);

	/**
	 * Verify CMS data signature
	 * 
	 * @param signedData
	 * @return
	 */
	public int verify(byte[] signedData) {
		if (signedData == null) {
			return ValidationError.CANNOT_LOAD_SIGNED_DATA;
		}

		Security.addProvider(new BouncyCastleProvider());

		CMSSignedData cms = null;
		try {
			cms = new CMSSignedData(signedData);
		} catch (CMSException e1) {
			LOG.error("CMSException: " + e1.getMessage());
		}
		if (cms == null) {
			return ValidationError.CANNOT_LOAD_SIGNED_DATA;
		}

		Store store = cms.getCertificates();
		SignerInformationStore signers = cms.getSignerInfos();
		Collection<?> c = signers.getSigners();
		Iterator<?> it = c.iterator();
		while (it.hasNext()) {
			SignerInformation signer = (SignerInformation) it.next();
			Collection<?> certCollection = store.getMatches(signer.getSID());
			Iterator<?> certIt = certCollection.iterator();
			X509CertificateHolder certHolder = (X509CertificateHolder) certIt
					.next();
			X509Certificate cert;
			try {
				cert = new JcaX509CertificateConverter().setProvider("BC")
						.getCertificate(certHolder);
				if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder()
						.setProvider("BC").build(cert))) {

					return CertificateValidator.verify(cert, null, new Date(),
							CertificateValidator.BOTH_OCSP_CRL);
				} else {
					// Chu ky da bi thay doi
					return ValidationError.SIGNATURE_INVALID;
				}
			} catch (CertificateException e) {
				LOG.error("CertificateException: " + e.getMessage());
				return ValidationError.SIGNER_CERTIFICATE_NOT_FOUND;
			} catch (OperatorCreationException e) {
				LOG.error("OperatorCreationException: " + e.getMessage());
				return ValidationError.SIGNATURE_NOT_FOUND;
			} catch (CMSException e) {
				LOG.error("CMSException: " + e.getMessage());
				// Expire or not yet valid
				if(e.getMessage().contains("")){
					return ValidationError.CMS_UNSIGN_DATA_NOT_FOUND;
				}
				return ValidationError.CERTIFICATE_NOT_YET_VALID;
			}
		}

		return ValidationError.SIGNATURE_VALID;
	}

	/**
	 * Get unsign data in CMS signature if available
	 * 
	 * @param signedData
	 *            Signed data
	 * @return
	 * @throws BkavSignaturesException
	 */
	public static byte[] getOriginalData(byte[] signedData)
			throws BkavSignaturesException {
		if (signedData == null) {
			throw new BkavSignaturesException("Input data null.");
		}

		Security.addProvider(new BouncyCastleProvider());

		CMSSignedData cms = null;
		try {
			cms = new CMSSignedData(signedData);
		} catch (CMSException e1) {
			throw new BkavSignaturesException("CMSException", e1);
		}
		CMSProcessableByteArray cpby = (CMSProcessableByteArray) cms
				.getSignedContent();
		byte[] data = (byte[]) cpby.getContent();
		return data;
	}
}
