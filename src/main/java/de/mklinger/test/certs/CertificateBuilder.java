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
	private X500Name subject;
	private X500NameBuilder subjectBuilder;
	private int validDays = 1;
	private int keySize = 4096;
	private final Supplier<BigInteger> serialFactory = new DefaultSerialSupplier();
	private CertificateAndKeyPair issuer;
	private boolean serverAuth;
	private boolean clientAuth;
	private List<String> ipSans;
	private List<String> dnsSans;

	public CertificateBuilder() {
		BouncyCastleImpl.installBouncyCastle();
	}

	public CertificateBuilder subject(final String subject) {
		this.subjectBuilder = null;
		this.subject = new X500Name(subject);
		return this;
	}

	public CertificateBuilder subjectCn(final String value) {
		this.subject = null;
		addSubjectRdn(BCStyle.CN, value);
		return this;
	}

	public CertificateBuilder subjectO(final String value) {
		this.subject = null;
		addSubjectRdn(BCStyle.O, value);
		return this;
	}

	public CertificateBuilder subjectOu(final String value) {
		this.subject = null;
		addSubjectRdn(BCStyle.OU, value);
		return this;
	}

	private void addSubjectRdn(final ASN1ObjectIdentifier oid, final String value) {
		if (this.subjectBuilder == null) {
			this.subjectBuilder = new X500NameBuilder();
		}
		this.subjectBuilder.addRDN(oid, value);
	}

	private X500Name getSubject() {
		if (subject != null) {
			return subject;
		} else if (subjectBuilder != null) {
			return subjectBuilder.build();
		} else {
			throw new CertificateBuildException("Missing subject");
		}
	}

	public CertificateBuilder validDays(final int validDays) {
		this.validDays = validDays;
		return this;
	}

	public CertificateBuilder keySize(final int keySize) {
		this.keySize = keySize;
		return this;
	}

	public CertificateBuilder issuer(final CertificateAndKeyPair issuer) {
		this.issuer = issuer;
		return this;
	}

	public CertificateBuilder serverAuth(final boolean serverAuth) {
		this.serverAuth = serverAuth;
		return this;
	}

	public CertificateBuilder clientAuth(final boolean clientAuth) {
		this.clientAuth = clientAuth;
		return this;
	}

	public CertificateBuilder ipSan(final String ipSan) {
		if (this.ipSans == null) {
			this.ipSans = new ArrayList<>();
		}
		this.ipSans.add(ipSan);
		return this;
	}

	public CertificateBuilder dnsSan(final String dnsSan) {
		if (this.dnsSans == null) {
			this.dnsSans = new ArrayList<>();
		}
		this.dnsSans.add(dnsSan);
		return this;
	}

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
