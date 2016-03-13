package com.bkav.bkavsignature.codesigning;

import java.io.File;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Date;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.bkav.bkavsignature.utils.CryptoToken;
import com.bkav.bkavsignature.utils.CryptoTokenUtil;
import com.bkav.bkavsignature.utils.FileUtil;

import net.jsign.PESigner;
import net.jsign.pe.PEFile;

public class ExeSigner {
	private static final String KEYSTOREPATH = "S:/WORK/2015/12-2015/540346B323887B4E02744AC4EC6D4460_Revoked_d3jpWqicAsRZ.p12";
	private static final String KEYSTOREPASS = "d3jpWqicAsRZ";

	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());
		String inputPath = "S:\\PROJECTS\\SIGNSERVER\\TestFiles\\authenticode\\input.dll";
		String outputPath = "C:\\Users\\BuiSi\\Desktop\\signed.dll";
		try {
			byte[] data = FileUtil.readBytesFromFile(inputPath);
			String tmpDirName = "C:\\Bkav\\BkavSignature\\tmp\\";
			File tmpDir = new File(tmpDirName);
			if (!tmpDir.exists()) {
				tmpDir.mkdirs();
			}
			Date d = new Date();
			String tmpFileName = tmpDirName + "tmp-" + d.getTime() + ".dll";
			FileUtil.writeToFile(data, tmpFileName);
			File file = new File(tmpFileName);

			PEFile peFile = new PEFile(file);
			System.out.println(peFile.getMachineType().toString());

			CryptoToken token = CryptoTokenUtil.initFromPKCS12(KEYSTOREPATH,
					KEYSTOREPASS);
			Certificate[] certChain = token.getCertChain();
			PrivateKey privateKey = token.getPrivateKey();

			PESigner signer = new PESigner(certChain, privateKey);
			signer.withProgramName("signed");
			signer.withTimestamping(false);
			signer.withTimestampingAutority("http://timestamp.verisign.com/scripts/timstamp.dll");
			signer.sign(peFile);

			byte[] signed = FileUtil.readBytesFromFile(tmpFileName);
			FileUtil.writeToFile(signed, outputPath);
			file.delete();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
