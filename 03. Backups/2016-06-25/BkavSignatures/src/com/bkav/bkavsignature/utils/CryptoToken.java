package com.bkav.bkavsignature.utils;

import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

/**
 * Created by BUISI on 3/22/2016.
 */
public class CryptoToken {
    private PrivateKey privateKey;
    private X509Certificate signerCert;
    private X509Certificate issuerCert;
    private Certificate[] certChain;
    private Provider privateKeyProvider;

    public CryptoToken() {
    }

    public CryptoToken(PrivateKey privKey, X509Certificate signer, X509Certificate issuer, Certificate[] certs, Provider provider) {
        this.setPrivateKey(privKey);
        this.setSignerCert(signer);
        this.setIssuerCert(issuer);
        this.setCertChain(certs);
        this.setPrivateKeyProvider(provider);
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public X509Certificate getSignerCert() {
        return signerCert;
    }

    public void setSignerCert(X509Certificate signerCert) {
        this.signerCert = signerCert;
    }

    public X509Certificate getIssuerCert() {
        return issuerCert;
    }

    public void setIssuerCert(X509Certificate issuerCert) {
        this.issuerCert = issuerCert;
    }

    public Certificate[] getCertChain() {
        return certChain;
    }

    public void setCertChain(Certificate[] certChain) {
        this.certChain = certChain;
    }

    public Provider getPrivateKeyProvider() {
        return privateKeyProvider;
    }

    public void setPrivateKeyProvider(Provider privateKeyProvider) {
        this.privateKeyProvider = privateKeyProvider;
    }
}
