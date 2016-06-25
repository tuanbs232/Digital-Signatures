package com.bkav.bkavsignature.xml;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.log4j.Logger;
import org.jcp.xml.dsig.internal.dom.DOMReference;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import com.bkav.bkavsignature.validationservice.CertificateValidator;
import com.bkav.bkavsignature.validationservice.ValidationError;

public class XMLValidator {
	private static final Logger LOG = Logger.getLogger(XMLValidator.class);

	/**
	 * Validate signed xml documet
	 * 
	 * @param data
	 *            byte array signed data
	 * @return verify code
	 * @see ValidationError
	 */
	public static int verify(byte[] data, int ocspOrCRL) {
		try {
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			Document doc = dbf.newDocumentBuilder()
					.parse(new ByteArrayInputStream(data));

			int verifySignature = verifySignature(doc, ocspOrCRL);

			return verifySignature;
		} catch (ParserConfigurationException ex) {
			LOG.error("ParserConfigurationException => " + ex.getMessage());
		} catch (SAXException ex) {
			LOG.error("SAXException => " + ex.getMessage());
		} catch (IOException ex) {
			LOG.error("IOException => " + ex.getMessage());
		}

		return ValidationError.CANNOT_LOAD_SIGNED_DATA;
	}

	/**
	 * Validate xml signature
	 * 
	 * @param doc
	 *            Signed xml document
	 * @return verify code
	 * @see ValidationError
	 */
	private static int verifySignature(Document doc, int ocspOrCRL) {
		boolean res = false;
		try {
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);

			NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS,
					"Signature");

			String providerName = System.getProperty("jsr105Provider",
					"org.jcp.xml.dsig.internal.dom.XMLDSigRI");

			XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM",
					(Provider) Class.forName(providerName).newInstance());
			

			for (int i = 0; i < nl.getLength();) {
				DOMValidateContext valContext = new DOMValidateContext(
						new XmlUtil.X509KeySelector(), nl.item(i));
				XMLSignature signature = fac.unmarshalXMLSignature(valContext);
				DOMReference reference = (DOMReference) signature
						.getSignedInfo().getReferences().get(0);
				if (reference.getURI().contains("#")) {
					String id = reference.getURI().replace("#", "");
					String expression = "//*[contains(@id,'" + id
							+ "') or contains(@iD ,'" + id
							+ "') or contains(@Id ,'" + id
							+ "') or contains(@ID ,'" + id + "')]";
					XPathFactory factory = XPathFactory.newInstance();
					XPath xpath = factory.newXPath();

					NodeList nodeList;
					try {
						nodeList = (NodeList) xpath.evaluate(expression, doc,
								XPathConstants.NODESET);
						for (int j = 0; j < nodeList.getLength(); j++) {
							Element e = (Element) nodeList.item(j);
							if (e.getAttribute("ID") != null
									&& !e.getAttribute("ID").equals("")) {
								e.setIdAttribute("ID", true);
							}
							if (e.getAttribute("id") != null
									&& !e.getAttribute("id").equals("")) {
								e.setIdAttribute("id", true);
							}
							if (e.getAttribute("iD") != null
									&& !e.getAttribute("iD").equals("")) {
								e.setIdAttribute("iD", true);
							}
							if (e.getAttribute("Id") != null
									&& !e.getAttribute("Id").equals("")) {
								e.setIdAttribute("Id", true);
							}
						}
					} catch (XPathExpressionException e) {
						e.printStackTrace();
					}
				}
				res = signature.validate(valContext);
				if (res) {
					Date signingTime = XmlUtil.getSigningTime(signature);
					
					Certificate[] certchain = XmlUtil
							.getCertificateChain(signature);
					X509Certificate signerCert = null;
					if (certchain != null && certchain.length > 0) {
						signerCert = (X509Certificate) certchain[0];
					}
					int certValid = CertificateValidator.verify(signerCert,
							certchain, signingTime, ocspOrCRL);

					return certValid;
				} else {
					return ValidationError.SIGNATURE_INVALID;
				}
			}

		} catch (XMLSignatureException ex) {
			LOG.error("XMLSignatureException => " + ex.getMessage());
			return ValidationError.SIGNATURE_INVALID;
		} catch (MarshalException ex) {
			LOG.error("MarshalException => " + ex.getMessage());
			return ValidationError.SIGNATURE_INVALID;
		} catch (InstantiationException ex) {
			LOG.error("InstantiationException => " + ex.getMessage());
			return ValidationError.SIGNATURE_INVALID;
		} catch (IllegalAccessException ex) {
			LOG.error("IllegalAccessException => " + ex.getMessage());
			return ValidationError.SIGNATURE_INVALID;
		} catch (ClassNotFoundException ex) {
			LOG.error("ClassNotFoundException => " + ex.getMessage());
			return ValidationError.SIGNATURE_INVALID;
		}
		if (res) {
			return ValidationError.SIGNATURE_VALID;
		} else {
			return ValidationError.SIGNATURE_INVALID;
		}
	}
}
