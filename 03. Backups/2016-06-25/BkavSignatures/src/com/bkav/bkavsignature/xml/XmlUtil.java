package com.bkav.bkavsignature.xml;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.log4j.Logger;
import org.jcp.xml.dsig.internal.dom.DOMSignatureProperties;
import org.jcp.xml.dsig.internal.dom.DOMSignatureProperty;
import org.jcp.xml.dsig.internal.dom.DOMXMLObject;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public class XmlUtil {

	private static final Logger LOG = Logger.getLogger(XmlUtil.class);

	public static class X509KeySelector extends KeySelector {

		@Override
		public KeySelectorResult select(KeyInfo keyInfo,
				KeySelector.Purpose purpose, AlgorithmMethod method,
				XMLCryptoContext context) throws KeySelectorException {
			Iterator<?> ki = keyInfo.getContent().iterator();
			while (ki.hasNext()) {
				XMLStructure info = (XMLStructure) ki.next();
				if (!(info instanceof X509Data)) {
					continue;
				}
				X509Data x509Data = (X509Data) info;
				Iterator<?> xi = x509Data.getContent().iterator();
				while (xi.hasNext()) {
					Object o = xi.next();
					if (!(o instanceof X509Certificate)) {
						continue;
					}
					final PublicKey key = ((X509Certificate) o).getPublicKey();
					// X509Certificate x509 = (X509Certificate) o;
					// Make sure the algorithm is compatible
					// with the method.
					if (algEquals(method.getAlgorithm(), key.getAlgorithm())) {
						return new KeySelectorResult() {
							@Override
							public Key getKey() {
								return key;
							}
						};
					}
				}
			}
			throw new KeySelectorException("No key found!");
		}

		static boolean algEquals(String algURI, String algName) {
			if ((algName.equalsIgnoreCase("DSA")
					&& algURI.equalsIgnoreCase(SignatureMethod.DSA_SHA1))
					|| (algName.equalsIgnoreCase("RSA") && algURI
							.equalsIgnoreCase(SignatureMethod.RSA_SHA1))) {
				return true;
			} else {
				return false;
			}
		}
	}

	public static class KeyValueKeySelector extends KeySelector {
		@Override
		public KeySelectorResult select(KeyInfo keyInfo,
				KeySelector.Purpose purpose, AlgorithmMethod method,
				XMLCryptoContext context) throws KeySelectorException {
			if (keyInfo == null) {
				throw new KeySelectorException("Null KeyInfo object!");
			}
			SignatureMethod sm = (SignatureMethod) method;
			List<?> list = keyInfo.getContent();

			for (int i = 0; i < list.size(); i++) {
				XMLStructure xmlStructure = (XMLStructure) list.get(i);
				if (xmlStructure instanceof KeyValue) {
					PublicKey pk = null;
					try {
						pk = ((KeyValue) xmlStructure).getPublicKey();
					} catch (KeyException ke) {
						throw new KeySelectorException(ke);
					}
					// make sure algorithm is compatible with method
					if (algEquals(sm.getAlgorithm(), pk.getAlgorithm())) {
						return new SimpleKeySelectorResult(pk);
					}
				}
			}
			throw new KeySelectorException("Element KeyValue not found!");
		}

		static boolean algEquals(String algURI, String algName) {
			if (algName.equalsIgnoreCase("DSA")
					&& algURI.equalsIgnoreCase(SignatureMethod.DSA_SHA1)) {
				return true;
			} else if (algName.equalsIgnoreCase("RSA")
					&& algURI.equalsIgnoreCase(SignatureMethod.RSA_SHA1)) {
				return true;
			} else {
				return false;
			}
		}
	}

	/**
	 * 
	 */
	private static class SimpleKeySelectorResult implements KeySelectorResult {

		private PublicKey pk;

		SimpleKeySelectorResult(PublicKey pk) {
			this.pk = pk;
		}

		@Override
		public Key getKey() {
			return pk;
		}
	}

	/**
	 * Get certificate chain from xml signed data
	 * 
	 * @param signedData
	 *            Xml signed data
	 * @return array certificate or maybe null
	 */
	public static Certificate[] getCertificateChain(byte[] signedData) {
		try {
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			Document doc = dbf.newDocumentBuilder()
					.parse(new ByteArrayInputStream(signedData));
			NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS,
					"Signature");

			String providerName = System.getProperty("jsr105Provider",
					"org.jcp.xml.dsig.internal.dom.XMLDSigRI");

			XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM",
					(Provider) Class.forName(providerName).newInstance());

			DOMValidateContext valContext = new DOMValidateContext(
					new XmlUtil.X509KeySelector(), nl.item(0));
			XMLSignature signature = fac.unmarshalXMLSignature(valContext);

			return getCertificateChain(signature);
		} catch (ParserConfigurationException ex) {
			LOG.error("ParserConfigurationException => " + ex.getMessage());
		} catch (SAXException ex) {
			LOG.error("SAXException => " + ex.getMessage());
		} catch (IOException ex) {
			LOG.error("IOException => " + ex.getMessage());
		} catch (InstantiationException e) {
			LOG.error("InstantiationException => " + e.getMessage());
		} catch (IllegalAccessException e) {
			LOG.error("IllegalAccessException => " + e.getMessage());
		} catch (ClassNotFoundException e) {
			LOG.error("ClassNotFoundException => " + e.getMessage());
		} catch (MarshalException e) {
			LOG.error("MarshalException => " + e.getMessage());
		}
		return null;
	}

	public static Certificate[] getCertificateChain(
			javax.xml.crypto.dsig.XMLSignature signature) {
		List<Certificate> result = new ArrayList<Certificate>();
		Iterator<?> ki = signature.getKeyInfo().getContent().iterator();
		while (ki.hasNext()) {
			XMLStructure info = (XMLStructure) ki.next();
			if (!(info instanceof X509Data)) {
				continue;
			}
			X509Data x509Data = (X509Data) info;
			Iterator<?> xi = x509Data.getContent().iterator();
			while (xi.hasNext()) {
				Object o = xi.next();
				if (!(o instanceof Certificate)) {
					continue;
				}
				result.add((Certificate) o);
			}
		}
		Certificate[] certChain = new Certificate[result.size()];
		certChain = result.toArray(certChain);

		return certChain;
	}

	public static PublicKey getPublicKey(XMLSignature signature) {
		List<?> list = signature.getKeyInfo().getContent();

		PublicKey result = null;

		for (int i = 0; i < list.size(); i++) {
			XMLStructure xmlStructure = (XMLStructure) list.get(i);
			if (xmlStructure instanceof KeyValue) {
				try {
					// TODO: Chua check signature method co match khong
					result = ((KeyValue) xmlStructure).getPublicKey();
					break;
				} catch (KeyException ke) {
					LOG.error("KEY EXCEPTION " + ke.getMessage());
				}
			}
		}

		return result;
	}

	// TODO: Can xem lai phan da chinh sua ben source signserver
	@SuppressWarnings("deprecation")
	public static Date getSigningTime(XMLSignature signature) {
		List<?> listReferences = signature.getObjects();
		String dateTime = "";
		for (Object o : listReferences) {
			if (o instanceof DOMXMLObject) {
				DOMXMLObject dom = (DOMXMLObject) o;
				List<?> list = dom.getContent();

				for (Object o1 : list) {
					if (o1 instanceof DOMSignatureProperties) {
						DOMSignatureProperties properties = (DOMSignatureProperties) o1;
						List<?> props = properties.getProperties();
						for (Object o2 : props) {
							if (o2 instanceof DOMSignatureProperty) {
								DOMSignatureProperty prop = (DOMSignatureProperty) o2;
								List<?> listProp = prop.getContent();
								for (Object o3 : listProp) {
									if (o3 instanceof DOMStructure) {
										DOMStructure structure = (DOMStructure) o3;
										Node node = structure.getNode();
										if ("DateTimeStamp"
												.equals(node.getNodeName())) {
											Long timeValue = new Long(
													node.getFirstChild()
															.getNodeValue());
											return new Date(timeValue);
										}
										if ("DATE".equalsIgnoreCase(
												node.getNodeName())
												|| "TIME".equalsIgnoreCase(
														node.getNodeName())
												|| "TIMEZONE".equalsIgnoreCase(
														node.getNodeName())) {
											String timeValue = node
													.getFirstChild()
													.getNodeValue();
											dateTime += timeValue + " ";
										}
									}
								}
							}
						}
					}
				}
			}
		}
		Date signTime = null;
		try {
			signTime = new Date(dateTime);
		} catch (Exception e) {
			signTime = new Date();
		}
		return signTime;
	}
}