package com.bkav.bkavsignature.utils;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Read/write file util class
 * 
 * @author BuiSi
 *
 */
public class FileUtil {

	/**
	 * Read all bytes from file to byte array
	 * 
	 * @param inputPath
	 *            input file directory
	 * @return a byte array
	 * @throws IOException
	 *             when file not found or something else
	 */
	public static byte[] readBytesFromFile(String inputPath)
			throws IOException {
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

	/**
	 * Remove temporary file when not use
	 * 
	 * @param file
	 *            file to remove
	 */
	public static void removeTmpFile(File file) {
		file.delete();
	}

	/**
	 * Write byte array to file
	 * 
	 * @param input
	 *            byte array file encode
	 * @param pathname
	 *            output file directory
	 */
	public static void writeToFile(byte[] input, String pathname) {
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
}
