package de.mklinger.test.certs;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;

import de.mklinger.micro.annotations.VisibleForTesting;

/**
 * Certificate builder.
 *
 * <p>Example Usage:</p>
 * <pre>
 * CertificateAndKeyPair certificateAndKeyPair = new CertificateBuilder()
 *     .subjectCn("my-certificate")
 *     .subjectO("My Organization")
 *     .validDays(365)
 *     .serverAuth(true)
 *     .clientAuth(true)
 *     .ipSan("127.0.0.1")
 *     .dnsSan("mklinger.de")
 *     .build();
 * </pre>
 *
 * @author Marc Klinger - mklinger[at]mklinger[dot]de
 */
public class CertificateBuilder {
	private static final int DEFAULT_VALID_DAYS = 1;
	private static final int DEFAULT_KEY_SIZE = 4096;

	private X500Name subject;
	private X500NameBuilder subjectBuilder;
	private int validDays = DEFAULT_VALID_DAYS;
	private int keySize = DEFAULT_KEY_SIZE;
	private final Supplier<BigInteger> serialFactory = new DefaultSerialSupplier();
	private CertificateAndKeyPair issuer;
	private boolean serverAuth;
	private boolean clientAuth;
	private List<String> ipSans;
	private List<String> dnsSans;

	public CertificateBuilder() {
		BouncyCastleImpl.installBouncyCastle();
	}

	/**
	 * Set full subject.
	 * <p>
	 * This will erase data set by the other {@code subject*()} methods.
	 * </p>
	 */
	public CertificateBuilder subject(final String subject) {
		this.subjectBuilder = null;
		this.subject = new X500Name(subject);
		return this;
	}

	/**
	 * Set subject value by OID.
	 * <p>
	 * This will erase data set by the {@link #subject(String)} method.
	 * </p>
	 */
	public CertificateBuilder subject(final String oid, final String value) {
		this.subject = null;
		addSubjectRdn(new ASN1ObjectIdentifier(oid), value);
		return this;
	}

	/**
	 * Set subject "common name".
	 * <p>
	 * This will erase data set by the {@link #subject(String)} method.
	 * </p>
	 */
	public CertificateBuilder subjectCn(final String value) {
		this.subject = null;
		addSubjectRdn(BCStyle.CN, value);
		return this;
	}

	/**
	 * Set subject "country code".
	 * <p>
	 * This will erase data set by the {@link #subject(String)} method.
	 * </p>
	 */
	public CertificateBuilder subjectC(final String value) {
		this.subject = null;
		addSubjectRdn(BCStyle.C, value);
		return this;
	}

	/**
	 * Set subject "organization".
	 * <p>
	 * This will erase data set by the {@link #subject(String)} method.
	 * </p>
	 */
	public CertificateBuilder subjectO(final String value) {
		this.subject = null;
		addSubjectRdn(BCStyle.O, value);
		return this;
	}

	/**
	 * Set subject "organizational unit name".
	 * <p>
	 * This will erase data set by the {@link #subject(String)} method.
	 * </p>
	 */
	public CertificateBuilder subjectOu(final String value) {
		this.subject = null;
		addSubjectRdn(BCStyle.OU, value);
		return this;
	}

	/**
	 * Set subject "Title".
	 * <p>
	 * This will erase data set by the {@link #subject(String)} method.
	 * </p>
	 */
	public CertificateBuilder subjectT(final String value) {
		this.subject = null;
		addSubjectRdn(BCStyle.T, value);
		return this;
	}

	/**
	 * Set subject "Street".
	 * <p>
	 * This will erase data set by the {@link #subject(String)} method.
	 * </p>
	 */
	public CertificateBuilder subjectStreet(final String value) {
		this.subject = null;
		addSubjectRdn(BCStyle.STREET, value);
		return this;
	}

	/**
	 * Set subject "locality name".
	 * <p>
	 * This will erase data set by the {@link #subject(String)} method.
	 * </p>
	 */
	public CertificateBuilder subjectL(final String value) {
		this.subject = null;
		addSubjectRdn(BCStyle.L, value);
		return this;
	}

	/**
	 * Set subject "state, or province name".
	 * <p>
	 * This will erase data set by the {@link #subject(String)} method.
	 * </p>
	 */
	public CertificateBuilder subjectSt(final String value) {
		this.subject = null;
		addSubjectRdn(BCStyle.ST, value);
		return this;
	}

	private void addSubjectRdn(final ASN1ObjectIdentifier oid, final String value) {
		if (this.subjectBuilder == null) {
			this.subjectBuilder = new X500NameBuilder();
		}
		this.subjectBuilder.addRDN(oid, value);
	}

	@VisibleForTesting
	protected X500Name getSubject() {
		if (subject != null) {
			return subject;
		} else if (subjectBuilder != null) {
			return subjectBuilder.build();
		} else {
			throw new CertificateBuildException("Missing subject");
		}
	}

	/**
	 * Set validity in days. Default is {@value #DEFAULT_VALID_DAYS}.
	 */
	public CertificateBuilder validDays(final int validDays) {
		this.validDays = validDays;
		return this;
	}

	/**
	 * Set the key size to be used. Default is {@value #DEFAULT_KEY_SIZE}.
	 */
	public CertificateBuilder keySize(final int keySize) {
		this.keySize = keySize;
		return this;
	}

	/**
	 * Set the issuer. The resulting certificate will be signed by the given
	 * certificate.
	 */
	public CertificateBuilder issuer(final CertificateAndKeyPair issuer) {
		this.issuer = issuer;
		return this;
	}

	/**
	 * Enable extended key usage for server auth. Required for a server certificate.
	 */
	public CertificateBuilder serverAuth() {
		return this.serverAuth(true);
	}

	/**
	 * Enable or disable extended key usage for server auth. Required for a server
	 * certificate.
	 */
	public CertificateBuilder serverAuth(final boolean serverAuth) {
		this.serverAuth = serverAuth;
		return this;
	}

	/**
	 * Enable extended key usage for client auth. Required for a client certificate.
	 */
	public CertificateBuilder clientAuth() {
		return this.clientAuth(true);
	}

	/**
	 * Enable or disable extended key usage for client auth. Required for a client
	 * certificate.
	 */
	public CertificateBuilder clientAuth(final boolean clientAuth) {
		this.clientAuth = clientAuth;
		return this;
	}

	/**
	 * Add an IP address as subject alternative name (SAN).
	 */
	public CertificateBuilder ipSan(final String ipSan) {
		if (this.ipSans == null) {
			this.ipSans = new ArrayList<>();
		}
		this.ipSans.add(ipSan);
		return this;
	}

	/**
	 * Add a DNS name as subject alternative name (SAN).
	 */
	public CertificateBuilder dnsSan(final String dnsSan) {
		if (this.dnsSans == null) {
			this.dnsSans = new ArrayList<>();
		}
		this.dnsSans.add(dnsSan);
		return this;
	}

	/**
	 * Generate keys and certificate.
	 */
	public CertificateAndKeyPair build() {
		if (issuer != null || haveExtensions()) {
			return buildV3();
		} else {
			return buildV1();
		}
	}

	private boolean haveExtensions() {
		return serverAuth || clientAuth ||
				(ipSans != null && !ipSans.isEmpty()) ||
				(dnsSans != null && !dnsSans.isEmpty());
	}

	private CertificateAndKeyPair buildV1() {
		final KeyPair keyPair = BouncyCastleImpl.generateRSAKeyPair(keySize);

		final X509CertificateHolder certificateHolder = BouncyCastleImpl.generateV1Certificate(
				keyPair,
				getSubject(),
				serialFactory.get(),
				validDays);

		final Certificate certificate = BouncyCastleImpl.toJcaCertificate(certificateHolder);

		return new CertificateAndKeyPair(certificateHolder, certificate, keyPair);
	}

	private CertificateAndKeyPair buildV3() {
		final KeyPair keyPair = BouncyCastleImpl.generateRSAKeyPair(keySize);

		X509CertificateHolder issuerCertificateHolder;
		if (issuer == null) {
			issuerCertificateHolder = null;
		} else {
			issuerCertificateHolder = issuer.getBcCertificateHolder();
		}

		final X509v3CertificateBuilder certBuilder = BouncyCastleImpl.baseCertBuilder(
				issuerCertificateHolder,
				keyPair,
				getSubject(),
				serialFactory.get(),
				validDays);

		BouncyCastleImpl.addAuthExtension(certBuilder, serverAuth, clientAuth);

		BouncyCastleImpl.addSanExtension(certBuilder, ipSans, dnsSans);

		final ContentSigner contentSigner = BouncyCastleImpl.contentSigner(keyPair.getPrivate());
		final X509CertificateHolder certificateHolder = certBuilder.build(contentSigner);

		final Certificate certificate = BouncyCastleImpl.toJcaCertificate(certificateHolder);

		return new CertificateAndKeyPair(certificateHolder, certificate, keyPair);
	}

	private static class DefaultSerialSupplier implements Supplier<BigInteger> {
		private static final AtomicLong next = new AtomicLong();

		@Override
		public BigInteger get() {
			final long current = next.getAndIncrement();
			return BigInteger.valueOf(current);
		}
	}
}
