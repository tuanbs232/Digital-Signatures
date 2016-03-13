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

import com.bkav.bkavsignature.utils.CryptoToken;
import com.bkav.bkavsignature.utils.CryptoTokenUtil;
import com.bkav.bkavsignature.utils.FileUtil;

public class XMLSigner {
	//private static final String KEYSTOREPATH = "S:/WORK/2016/01-2016/BCSE_Client.p12";
	//private static final String KEYSTOREPASS = "12345678";
	private static final String KEYSTOREPATH="E:\\Company\\BKAV\\Code_Demo\\TuanBS4.p12";
    private static final String KEYSTOREPASS="1";
	private static final String SIGNINGTIME_ID = "SigningTime";
	// private final String USER_SIGNNINGTIME_ID = "TimeSignatureUSER";
	private static final String SIGNINGTIME_URI = "signatureProperties";
	private static final String SIGNINGTIME_TAGNAME = "DateTimeStamp";
	
	public static void main(String[] args) {
//		String filePath = "S:/WORK/2016/01-2016/input.xml";
//		String signedPath = "C:\\Users\\BuiSi\\Desktop\\signed.xml";
		String filePath = "E:\\Company\\BKAV\\Code_Demo\\demo.xml";
		String signedPath = "E:\\Company\\BKAV\\Code_Demo\\aa.xml";
		try {
			byte[] data = FileUtil.readBytesFromFile(filePath);
			byte[] signed = sign(data);
			FileUtil.writeToFile(signed, signedPath);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public static byte[] sign(byte[] data){
        String providerName = System.getProperty("jsr105Provider",
                "org.jcp.xml.dsig.internal.dom.XMLDSigRI");
        XMLSignatureFactory fac = null;
        try {
            fac = XMLSignatureFactory.getInstance("DOM", 
                    (Provider)Class.forName(providerName).newInstance());
        } catch (InstantiationException e) {
        } catch (IllegalAccessException e) {
        } catch (ClassNotFoundException e) {
        }
        
        CryptoToken token = CryptoTokenUtil.initFromPKCS12(KEYSTOREPATH, KEYSTOREPASS);

        PrivateKey privKey = token.getPrivateKey();
        Certificate[] certs = token.getCertChain();
        List<Certificate> certChain = new ArrayList<Certificate>(); 
        for(Certificate c : certs){
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

            si = fac.newSignedInfo(fac.newCanonicalizationMethod(
                    CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS,
                    (XMLStructure) null),
                    fac.newSignatureMethod(getSignatureMethod(privKey), null),
                    Collections.singletonList(ref));

        } catch (InvalidAlgorithmParameterException e) {
        } catch (NoSuchAlgorithmException e) {
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
            doc = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(data));

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
            DOMSignContext dsc = new DOMSignContext(privKey, doc.getDocumentElement());
            XMLSignature signature = fac.newXMLSignature(si, ki,
					Collections.singletonList(object), null, null);
            signature.sign(dsc);
        } catch (ParserConfigurationException ex) {
        } catch (SAXException ex) {
        } catch (IOException ex) {
        } catch (MarshalException ex) {
        } catch (XMLSignatureException ex) {
        }

        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans;
        try {
            trans = tf.newTransformer();
            trans.transform(new DOMSource(doc), new StreamResult(bout));
        } catch (TransformerConfigurationException ex) {
        } catch (TransformerException ex) {
        }

        byte[] signedbytes = bout.toByteArray();
        
        return signedbytes;
	}
	
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
