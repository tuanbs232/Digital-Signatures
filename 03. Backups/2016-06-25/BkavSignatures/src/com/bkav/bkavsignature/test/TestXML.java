package com.bkav.bkavsignature.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import com.bkav.bkavsignature.utils.BkavSignaturesException;
import com.bkav.bkavsignature.utils.CryptoToken;
import com.bkav.bkavsignature.utils.CryptoTokenUtil;
import com.bkav.bkavsignature.utils.FileUtil;
import com.bkav.bkavsignature.xml.XMLSigner;

public class TestXML {
	private static final Logger LOG = Logger.getLogger(TestXML.class);

	public static void main(String[] args) {
		signTestPkcs11();
	}
	
	public static void signTestCSP(){
		String inputPath = "S:/WORK/2016/05-2016/Test_Files/input.xml";
		String serial = "65d6c0903341fe8d";
		CryptoToken token = null;
		try {
			token =CryptoTokenUtil.initFromTokenCSP(serial);
			XMLSigner.sign(FileUtil.readBytesFromFile(inputPath), token);
		} catch (IOException e) {
			e.printStackTrace();
		} catch (BkavSignaturesException e) {
			e.printStackTrace();
		}
	}
	
	public static void signTestPkcs11(){
		String inputPath = "S:/WORK/2016/05-2016/Test_Files/input.xml";
		String configDir = "S:/WORK/2016/06-2016/E-Token/config.cfg";
		CryptoToken token = null;
		try {
			token = CryptoTokenUtil.initFromPkcs11(configDir, "12345678");
		} catch (BkavSignaturesException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		try {
			XMLSigner.sign(FileUtil.readBytesFromFile(inputPath), token);
		} catch (IOException e) {
			e.printStackTrace();
		} catch (BkavSignaturesException e) {
			e.printStackTrace();
		}
	}

	public static void test(byte[] data) {
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		Document doc = null;
		try {
			String NODE_NAME = "HSoKhaiThue";
			doc = dbf.newDocumentBuilder()
					.parse(new ByteArrayInputStream(data));
			NodeList nodeSignList = doc.getElementsByTagName(NODE_NAME);
			if (nodeSignList.getLength() > 0) {
				Element e = (Element) nodeSignList.item(0);
				LOG.info(e.getAttribute("ID") == "");
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
		} catch (SAXException e) {
			LOG.error(e.getCause());
		} catch (IOException e) {
			LOG.error(e.getCause());
		} catch (ParserConfigurationException e) {
			LOG.error(e.getCause());
		}
	}
}
