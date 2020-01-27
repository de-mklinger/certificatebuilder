package de.mklinger.test.certs;

import java.security.KeyPair;
import java.security.cert.Certificate;

import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Holds a certificate with its private and public key.
 *
 * @author Marc Klinger - mklinger[at]mklinger[dot]de
 */
public class CertificateAndKeyPair {
	private final X509CertificateHolder bcCertificateHolder;
	private final Certificate certificate;
	private final KeyPair keyPair;

	public CertificateAndKeyPair(final X509CertificateHolder bcCertificateHolder, final Certificate certificate, final KeyPair keyPair) {
		this.bcCertificateHolder = bcCertificateHolder;
		this.certificate = certificate;
		this.keyPair = keyPair;
	}

	X509CertificateHolder getBcCertificateHolder() {
		return bcCertificateHolder;
	}

	public Certificate getCertificate() {
		return certificate;
	}

	public KeyPair getKeyPair() {
		return keyPair;
	}
}