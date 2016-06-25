package com.bkav.bkavsignature.jar;

import java.io.IOException;
import java.io.OutputStream;

import sun.misc.BASE64Encoder;

class JarBASE64Encoder extends BASE64Encoder {
	/**
	 * Encode the suffix that ends every output line.
	 */
	protected void encodeLineSuffix(OutputStream aStream) throws IOException {
	}
}