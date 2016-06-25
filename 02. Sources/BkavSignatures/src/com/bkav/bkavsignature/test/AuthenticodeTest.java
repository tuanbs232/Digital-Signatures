package com.bkav.bkavsignature.test;

import java.io.IOException;

import com.bkav.bkavsignature.codesigning.ExeSigner;
import com.bkav.bkavsignature.utils.BkavSignaturesException;
import com.bkav.bkavsignature.utils.CryptoToken;
import com.bkav.bkavsignature.utils.CryptoTokenUtil;
import com.bkav.bkavsignature.utils.FileUtil;

public class AuthenticodeTest {
	public static void main(String[] args) {
		sign();
	}

	public static void sign() {
		String inputPath = "S:/WORK/2016/05-2016/Test_files/BkavCA_s.dll";
		String configDir = "S:/WORK/2016/06-2016/E-Token/config.cfg";
		String pin = "12345678";

		CryptoToken token = null;
		try {
			token = CryptoTokenUtil.initFromPkcs11(configDir, pin);
		} catch (BkavSignaturesException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		if (token == null) {
			System.out.println("Token null");
			return;
		}

		try {
			byte[] unSign = FileUtil.readBytesFromFile(inputPath);
			byte[] signed = ExeSigner.sign(unSign, token, null);
			signed.notify();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BkavSignaturesException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
