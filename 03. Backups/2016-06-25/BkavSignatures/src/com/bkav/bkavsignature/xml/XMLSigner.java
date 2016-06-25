package com.bkav.bkavsignature.xml;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignatureProperties;
import javax.xml.crypto.dsig.SignatureProperty;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

import com.bkav.bkavsignature.utils.BkavSignaturesException;
import com.bkav.bkavsignature.utils.CryptoToken;

/**
 * Class perform create xml signature
 * 
 * @author TuanBS (tuanbs@bkav.com)
 *
 */
public class XMLSigner {
	// Properties for add signing time
	private static final String SIGNINGTIME_ID = "SigningTime";
	private static final String SIGNINGTIME_URI = "signatureProperties";
	private static final String SIGNINGTIME_TAGNAME = "DateTimeStamp";

	/**
	 * Create xml signature from bytes array data and CryptoToken object
	 * 
	 * @param data
	 *            Bytes array data to sign
	 * @param token
	 *            CryptoToken object contain all key and certificates
	 * @return Bytes array signed data or exception
	 * @throws BkavSignaturesException
	 */
	public static byte[] sign(byte[] data, CryptoToken token)
			throws BkavSignaturesException {
		// Check null parameters
		if (data == null) {
			throw new BkavSignaturesException("Data null.");
		}
		if (token == null) {
			throw new BkavSignaturesException("CryptoToken null.");
		}

		// Specify XML signature provider
		// Use org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI
		// Instead of org.jcp.xml.dsig.internal.dom.XMLDSigRI
		String providerName = System.getProperty("jsr105Provider",
				"org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI");
		XMLSignatureFactory fac = null;
		try {
			fac = XMLSignatureFactory.getInstance("DOM",
					(Provider) Class.forName(providerName).newInstance());
		} catch (InstantiationException e) {
			throw new BkavSignaturesException("InstantiationException", e);
		} catch (IllegalAccessException e) {
			throw new BkavSignaturesException("IllegalAccessException", e);
		} catch (ClassNotFoundException e) {
			providerName = System.getProperty("jsr105Provider",
					"org.jcp.xml.dsig.internal.dom.XMLDSigRI");
			try {
				fac = XMLSignatureFactory.getInstance("DOM",
						(Provider) Class.forName(providerName).newInstance());
			} catch (InstantiationException e1) {
				throw new BkavSignaturesException("InstantiationException", e);
			} catch (IllegalAccessException e1) {
				throw new BkavSignaturesException("IllegalAccessException", e);
			} catch (ClassNotFoundException e1) {
				throw new BkavSignaturesException("ClassNotFoundException", e);
			}
		}

		// Init signer
		PrivateKey privKey = token.getPrivateKey();
		if (privKey == null) {
			throw new BkavSignaturesException(
					"CryptoToken not contain private key.");
		}
		Certificate[] certs = token.getCertChain();
		if (certs == null) {
			throw new BkavSignaturesException(
					"CryptoToken not contain certchain.");
		}
		List<Certificate> certChain = new ArrayList<Certificate>();
		for (Certificate c : certs) {
			certChain.add(c);
		}

		// Get certificate chain and signer certificate
		SignedInfo si = null;
		try {
			Reference ref = fac.newReference("",
					fac.newDigestMethod(DigestMethod.SHA1, null),
					Collections.singletonList(fac.newTransform(
							Transform.ENVELOPED, (XMLStructure) null)),
					null, null);

			si = fac.newSignedInfo(
					fac.newCanonicalizationMethod(
							CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS,
							(XMLStructure) null),
					fac.newSignatureMethod(getSignatureMethod(privKey), null),
					Collections.singletonList(ref));

		} catch (InvalidAlgorithmParameterException e) {
			throw new BkavSignaturesException(
					"InvalidAlgorithmParameterException", e);
		} catch (NoSuchAlgorithmException e) {
			throw new BkavSignaturesException("NoSuchAlgorithmException", e);
		}

		KeyInfoFactory kif = fac.getKeyInfoFactory();
		X509Data x509d = kif.newX509Data(certChain);

		List<XMLStructure> kviItems = new LinkedList<XMLStructure>();
		kviItems.add(x509d);
		KeyInfo ki = kif.newKeyInfo(kviItems);

		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		Document doc = null;
		try {
			doc = dbf.newDocumentBuilder()
					.parse(new ByteArrayInputStream(data));

			Node node = null;
			node = doc.createElement(SIGNINGTIME_TAGNAME);
			long signTime = (new Date()).getTime();
			node.appendChild(doc.createTextNode("" + signTime));
			DOMStructure timeStructure = new DOMStructure(node);

			SignatureProperty signTimeProperty = fac.newSignatureProperty(
					Collections.singletonList(timeStructure), SIGNINGTIME_URI,
					SIGNINGTIME_ID);
			SignatureProperties properties = fac.newSignatureProperties(
					Collections.singletonList(signTimeProperty), "");
			XMLObject object = fac.newXMLObject(
					Collections.singletonList(properties), "object-1", null,
					null);
			DOMSignContext dsc = new DOMSignContext(privKey,
					doc.getDocumentElement());
			XMLSignature signature = fac.newXMLSignature(si, ki,
					Collections.singletonList(object), null, null);
			signature.sign(dsc);
		} catch (ParserConfigurationException ex) {
			throw new BkavSignaturesException("ParserConfigurationException",
					ex);
		} catch (SAXException ex) {
			throw new BkavSignaturesException("SAXException", ex);
		} catch (IOException ex) {
			throw new BkavSignaturesException("IOException", ex);
		} catch (MarshalException ex) {
			throw new BkavSignaturesException("MarshalException", ex);
		} catch (XMLSignatureException ex) {
			throw new BkavSignaturesException("XMLSignatureException", ex);
		}

		ByteArrayOutputStream bout = new ByteArrayOutputStream();
		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer trans;
		try {
			trans = tf.newTransformer();
			trans.transform(new DOMSource(doc), new StreamResult(bout));
		} catch (TransformerConfigurationException ex) {
			throw new BkavSignaturesException(
					"TransformerConfigurationException", ex);
		} catch (TransformerException ex) {
			throw new BkavSignaturesException("TransformerException", ex);
		}

		byte[] signedbytes = bout.toByteArray();

		return signedbytes;
	}

	/**
	 * Get signature method of private key
	 * 
	 * @param key
	 *            private key in cryptotoken object
	 * @return String method name
	 */
	private static String getSignatureMethod(PrivateKey key) {
		String result = "";
		if ("DSA".equals(key.getAlgorithm())) {
			result = SignatureMethod.DSA_SHA1;
		}
		if ("RSA".equals(key.getAlgorithm())) {
			result = SignatureMethod.RSA_SHA1;
		}
		return result;
	}
}
