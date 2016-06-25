package com.bkav.bkavsignature.utils;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;

/**
 * Common util methods
 * 
 * @author TuanBS (tuanbs@bkav.com)
 *
 */
public class CommonUtils {


	/**
	 * Check connect to tsa responder
	 *
	 * @param destinationUrl
	 *            TSA server's address
	 * @param fireRequest
	 *            check response data
	 * @param timeout
	 *            connection's timeout
	 * @return null if connection ok, exception message if not
	 */
	public static String getAccessError(String destinationUrl,
			boolean fireRequest, int timeout) {
		URL url;
		try {
			url = new URL(destinationUrl);
		} catch (MalformedURLException e) {
			throw new IllegalArgumentException("Invalid destination URL", e);
		}

		HttpURLConnection conn = null;
		try {
			conn = (HttpURLConnection) url.openConnection();

			// set specified timeout if non-zero
			if (timeout != 0) {
				conn.setConnectTimeout(timeout);
				conn.setReadTimeout(timeout);
			}

			conn.setDoOutput(false);
			conn.setDoInput(true);

			/*
			 * if connecting is not possible this will throw a connection
			 * refused exception
			 */
			conn.connect();

			// TODO need more research
			int responseCode = conn.getResponseCode();
			if (responseCode == 406 || responseCode == 200) {
				return null;
			}

			if (fireRequest) {
				InputStream is = null;
				try {
					is = conn.getInputStream();
				} finally {
					if (is != null) {
						is.close();
					}
				}

			}
			/* if connecting is possible we return true here */
			return null;

		} catch (IOException e) {
			/* exception is thrown -> server not available */
			return e.getClass().getName() + ": " + e.getMessage();
		} finally {
			if (conn != null) {
				conn.disconnect();
			}
		}
	}
}
