package com.bkav.bkavsignature.utils;

public class BkavSignaturesException extends Exception{

	/**
	 * 
	 */
	private static final long serialVersionUID = -3903529918407257410L;
	
	public BkavSignaturesException(String message){
		super(message);
	}
	
	public BkavSignaturesException(String message, Throwable e){
		super(message, e);
	}
}
