package com.bkav.bkavsignature.validationservice;

public interface ValidationError {
	public static final int CANNOT_LOAD_SIGNED_DATA = -1;
	public static final int SIGNATURE_NOT_FOUND = -2;
	public static final int SIGNATURE_INVALID = -3;
	public static final int TRUSTPATH_INVALID = -4;
	public static final int CERTCHAIN_NOT_FOUND = -5;
	public static final int CERTIFICATE_NOT_YET_VALID = 1;
	public static final int CERTIFICATE_EXPIRED = 2;
	public static final int KEY_USAGE_NOT_ALLOW = 3;
	public static final int CERTIFICATE_STATUS_REVOKED = 4;
	public static final int CERTIFICATE_STATUS_UNKNOWN = 5;
	public static final int OCSP_URL_NOT_FOUND = 6;
	public static final int SIGNER_CERTIFICATE_NOT_FOUND = 7;
	public static final int OCSP_RESPONSE_NULL = 8;
	public static final int CRL_NOT_FOUND = 9;
	public static final int OCSP_RESPONDER_NOT_FOUND = 10;
	public static final int OCSP_SIGNATURE_INVALID = 11;
	public static final int CANNOT_CREATE_OCSP_REQUEST = 12;
	//Khong kiem tra duoc chu ky cua CA tren signer's Certificate
	public static final int CERTIFICATE_SIGNATURE_FAILED = 13;
	public static final int CMS_UNSIGN_DATA_NOT_FOUND = 14;
	
	public static final int SIGNATURE_VALID = 0;
	public static final int CERTIFICATE_STATUS_GOOD = 0;
}
