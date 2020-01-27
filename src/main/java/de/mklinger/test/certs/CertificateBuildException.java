package de.mklinger.test.certs;

/**
 * Unchecked exception, thrown when something goes wrong while building a
 * certificate.
 *
 * @author Marc Klinger - mklinger[at]mklinger[dot]de
 */
public class CertificateBuildException extends RuntimeException {
	private static final long serialVersionUID = 1L;

	public CertificateBuildException(final Throwable cause) {
		super(cause);
	}

	public CertificateBuildException(final String message) {
		super(message);
	}
}