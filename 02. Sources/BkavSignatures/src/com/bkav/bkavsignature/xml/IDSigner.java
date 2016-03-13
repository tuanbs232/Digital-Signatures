package com.bkav.bkavsignature.xml;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

public class IDSigner {
	private final String KEYSTOREPATH = "S:/WORK/2016/01-2016/test_Ng2v2m0dJcQXhdav9FqF.p12";
	private final String KEYSTOREPASS = "Ng2v2m0dJcQXhdav9FqF";
//	private final String NODE_NAME = "DKyThue";
	private String NODE_ID = "_NODE_TO_SIGN";

	private final String TVAN_SIGNINGTIME_ID = "TimeSignatureBKAV";
	// private final String USER_SIGNNINGTIME_ID = "TimeSignatureUSER";
//	private final String SIGNINGTIME_URI = "signatureProperties";
//	private final String SIGNINGTIME_TAGNAME = "DateTimeStamp";

	private final String CONFIG = "S:/WORK/PROJECTS/Bkav_Token_config/config.cfg";
	private final String USERPIN = "12345678";

	private PrivateKey privKey;
	private Certificate cert;
	private List<X509Certificate> certChain = new ArrayList<X509Certificate>();

	public static void main(String[] args) {
		String unsign = "C:\\Users\\BuiSi\\Desktop\\sign_1.xml";
		String signed = "C:\\Users\\BuiSi\\Desktop\\xpath_signed.xml";

		IDSigner signer = new IDSigner();

		signer.initCrypto();
		byte[] data;
		try {
			String nodeName = "DKyThue";
			String parrentNode = "CKyDTu";
			data = signer.readBytesFromFile(unsign);
			signer.writeToFile(signer.sign(data, nodeName, parrentNode), signed);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private byte[] readBytesFromFile(String inputPath) throws IOException {
		ByteArrayOutputStream ous = null;
		InputStream ios = null;
		try {
			byte[] buffer = new byte[4096];
			ous = new ByteArrayOutputStream();
			ios = new FileInputStream(new File(inputPath));
			int read = 0;
			while ((read = ios.read(buffer)) != -1) {
				ous.write(buffer, 0, read);
			}
		} finally {
			try {
				if (ous != null)
					ous.close();
			} catch (IOException e) {
			}

			try {
				if (ios != null)
					ios.close();
			} catch (IOException e) {
			}
		}
		return ous.toByteArray();

	}

	public void writeToFile(byte[] input, String pathname) {
		FileOutputStream outStream = null;
		try {
			outStream = new FileOutputStream(new File(pathname));
			outStream.write(input);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			if (outStream != null) {
				try {
					outStream.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
	}

	public byte[] sign(byte[] data, String nodeName, String parrentNode) {
		byte[] signedbytes = null;
		initCrypto();
		// initTokenCrypto();
//		String providerName = System.getProperty("jsr105Provider", "org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI");
//		XMLSignatureFactory fac = null;
//		try {
//		    fac = XMLSignatureFactory.getInstance("DOM", (Provider) Class.forName(providerName).newInstance());
//		} catch (InstantiationException e) {
//		    e.printStackTrace();
//		} catch (IllegalAccessException e) {
//		    e.printStackTrace();
//		} catch (ClassNotFoundException e) {
//		    e.printStackTrace();
//		}
		
		XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		Document doc;
		try {
			// Load document to sign
			doc = dbf.newDocumentBuilder()
					.parse(new ByteArrayInputStream(data));

			Node nodeSign = doc.getElementsByTagName(nodeName).item(0);

			Element e = (Element) nodeSign;
			if (e.hasAttribute("id")) {
				e.setIdAttribute("id", true);
				NODE_ID = e.getAttribute("id");
			} else if (e.hasAttribute("iD")) {
				e.setIdAttribute("iD", true);
				NODE_ID = e.getAttribute("iD");
			} else if (e.hasAttribute("Id")) {
				e.setIdAttribute("Id", true);
				NODE_ID = e.getAttribute("Id");
			} else if (e.hasAttribute("ID")) {
				e.setIdAttribute("ID", true);
				NODE_ID = e.getAttribute("ID");
			} else {
				e.setAttribute("ID", NODE_ID);
				e.setIdAttribute("ID", true);
			}

			// Create SignedInfo Object
			SignedInfo si = createSignedInfo(fac, "#" + TVAN_SIGNINGTIME_ID);

			// Create KeyInfo Object
			KeyInfo ki = createKeyInfo(fac);
			// Create list objects contain sign time
//			long signTime = (new Date()).getTime();
//
//			// Create a node to store signing time
//			Node node = null;
//			node = doc.createElement(SIGNINGTIME_TAGNAME);
//			node.appendChild(doc.createTextNode("" + signTime));
//			DOMStructure timeStructure = new DOMStructure(node);
//
//			SignatureProperty signTimeProperty = fac.newSignatureProperty(
//					Collections.singletonList(timeStructure), SIGNINGTIME_URI,
//					TVAN_SIGNINGTIME_ID);
//			SignatureProperties properties = fac.newSignatureProperties(
//					Collections.singletonList(signTimeProperty), "");
//			XMLObject object = fac.newXMLObject(
//					Collections.singletonList(properties), "object-1", null,
//					null);

			// Get parent node to store signature
			Node xpathParrent = doc.getElementsByTagName(parrentNode).item(0);

			DOMSignContext dsc = new DOMSignContext(privKey, xpathParrent);

//			XMLSignature signature = fac.newXMLSignature(si, ki,
//					Collections.singletonList(object), null, null);
			XMLSignature signature = fac.newXMLSignature(si, ki,null, null, null);
			
			// Sign document
			signature.sign(dsc);

			// Get signed document as bytes array
			ByteArrayOutputStream bout = new ByteArrayOutputStream();
			TransformerFactory tf = TransformerFactory.newInstance();
			Transformer trans;
			trans = tf.newTransformer();
			trans.transform(new DOMSource(doc), new StreamResult(bout));

			signedbytes = bout.toByteArray();
			bout.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (SAXException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ParserConfigurationException e) {
			e.printStackTrace();
		} catch (MarshalException e) {
			e.printStackTrace();
		} catch (XMLSignatureException e) {
			e.printStackTrace();
		} catch (TransformerConfigurationException e) {
			e.printStackTrace();
		} catch (TransformerException e) {
			e.printStackTrace();
		} catch (KeyException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}

		return signedbytes;

	}

	private KeyInfo createKeyInfo(XMLSignatureFactory fac) throws KeyException {
		KeyInfoFactory kif = fac.getKeyInfoFactory();

		List<Serializable> x509Content = new ArrayList<Serializable>();

		if (cert instanceof X509Certificate) {
			X509Certificate signerCert = (X509Certificate) cert;
			x509Content.add(signerCert.getSubjectX500Principal().getName());
		} else {
			x509Content.add("");
		}
		x509Content.add(cert);
		X509Data x509d = kif.newX509Data(x509Content);

		List<XMLStructure> kviItems;
		kviItems = new LinkedList<XMLStructure>();
		kviItems.add(x509d);

		return kif.newKeyInfo(kviItems);
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	private SignedInfo createSignedInfo(final XMLSignatureFactory fac,
			String timeReferenceID) throws NoSuchAlgorithmException,
					InvalidAlgorithmParameterException {
		List<Transform> transformList = new ArrayList<Transform>();
		TransformParameterSpec tps = null;
		Transform envelopedTransform;
		try {
		    envelopedTransform = fac.newTransform(Transform.ENVELOPED,
		            tps);
		    Transform c14NTransform = fac.newTransform(
		            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315", tps);

		    transformList.add(envelopedTransform);
		    transformList.add(c14NTransform);
		} catch (NoSuchAlgorithmException e) {
		    throw new RuntimeException("Erro inesperado: " + e.getMessage(), e);
		} catch (InvalidAlgorithmParameterException e) {
		    throw new RuntimeException("Erro inesperado: " + e.getMessage(), e);
		}
		Reference ref = fac.newReference("#" + NODE_ID,
				fac.newDigestMethod(DigestMethod.SHA1, null), transformList, null,
				null);

		// Create a reference for signing time node
//		Reference timeRef = fac.newReference(timeReferenceID,
//				fac.newDigestMethod(DigestMethod.SHA1, null), null, null, null);

		List referenceList = new ArrayList();
		referenceList.add(ref);
//		referenceList.add(timeRef);

		SignedInfo si = fac.newSignedInfo(
				fac.newCanonicalizationMethod(
						CanonicalizationMethod.INCLUSIVE,
						(C14NMethodParameterSpec) null),
				fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null),
				referenceList);

		return si;
	}

	public void initCrypto() {
		try {
			KeyStore ks = KeyStore.getInstance("PKCS12");
			ks.load(new FileInputStream(new File(KEYSTOREPATH)),
					KEYSTOREPASS.toCharArray());

			String alias = ks.aliases().nextElement();

			privKey = (PrivateKey) ks.getKey(alias, KEYSTOREPASS.toCharArray());
			cert = ks.getCertificate(alias);
			System.out.println(((X509Certificate) cert).getIssuerX500Principal()
					.getName());
			Certificate[] certs = ks.getCertificateChain(alias);
			for (Certificate c : certs) {
				if (c instanceof X509Certificate) {
					certChain.add((X509Certificate) c);
				}
			}
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (UnrecoverableKeyException e) {
			e.printStackTrace();
		}

	}

	public void initTokenCrypto() {
//		FileInputStream fis;
//		try {
//			fis = new FileInputStream(new File(CONFIG));
//			Provider provider = new sun.security.pkcs11.SunPKCS11(fis);
//			Security.addProvider(provider);
//			KeyStore p11 = KeyStore.getInstance("PKCS11", provider);
//			p11.load(null, USERPIN.toCharArray());
//			String CERTLABEL = p11.aliases().nextElement();
//			privKey = (PrivateKey) p11.getKey(CERTLABEL, USERPIN.toCharArray());
//
//			cert = p11.getCertificate(CERTLABEL);
//
//			Certificate[] certs = p11.getCertificateChain(CERTLABEL);
//			for (Certificate c : certs) {
//				if (c instanceof X509Certificate) {
//					certChain.add((X509Certificate) c);
//				}
//			}
//
//		} catch (FileNotFoundException e) {
//			e.printStackTrace();
//		} catch (KeyStoreException e) {
//			e.printStackTrace();
//		} catch (NoSuchAlgorithmException e) {
//			e.printStackTrace();
//		} catch (CertificateException e) {
//			e.printStackTrace();
//		} catch (IOException e) {
//			e.printStackTrace();
//		} catch (UnrecoverableKeyException e) {
//			e.printStackTrace();
//		}
	}
}
