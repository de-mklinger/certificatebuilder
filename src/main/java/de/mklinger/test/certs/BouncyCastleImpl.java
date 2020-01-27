package de.mklinger.test.certs;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicReference;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNamesBuilder;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import de.mklinger.micro.annotations.Nullable;

class BouncyCastleImpl {
	private static final AtomicReference<SecureRandom> secureRandom = new AtomicReference<>();

	private static SecureRandom secureRandom() {
		return secureRandom.updateAndGet(current -> {
			if (current == null) {
				return new SecureRandom();
			} else {
				return current;
			}
		});
	}

	/** No instantiation */
	private BouncyCastleImpl() {}

	private static boolean isBcInstalled() {
		return Security.getProvider("BC") != null;
	}

	static void installBouncyCastle() {
		if (!isBcInstalled()) {
			Security.addProvider(new BouncyCastleProvider());
		}
		if (!isBcInstalled()) {
			throw new CertificateBuildException("Installing BouncyCastle security provider failed");
		}
	}

	static void addSanExtension(final X509v3CertificateBuilder certBuilder, final List<String> ipSans, final List<String> dnsSans) {
		wrapExceptions(() -> {
			doAddSanExtension(certBuilder, ipSans, dnsSans);
			return null;
		});
	}

	private static void doAddSanExtension(final X509v3CertificateBuilder certBuilder, final List<String> ipSans, final List<String> dnsSans) throws IOException {
		final boolean haveIpSans = ipSans != null && !ipSans.isEmpty();
		final boolean haveDnsSans = dnsSans != null && !dnsSans.isEmpty();
		final boolean haveSans = haveIpSans || haveDnsSans;
		if (haveSans) {
			final GeneralNamesBuilder generalNamesBuilder = new GeneralNamesBuilder();

			if (haveIpSans) {
				for (final String ipSan : ipSans) {
					generalNamesBuilder.addName(new GeneralName(GeneralName.iPAddress, ipSan));
				}
			}

			if(haveDnsSans) {
				for (final String dnsSan : dnsSans) {
					generalNamesBuilder.addName(new GeneralName(GeneralName.dNSName, dnsSan));
				}
			}

			final Extension extension = new Extension(
					Extension.subjectAlternativeName,
					false,
					generalNamesBuilder.build().getEncoded());

			certBuilder.addExtension(extension);
		}
	}

	static void addAuthExtension(final X509v3CertificateBuilder certBuilder, final boolean serverAuth, final boolean clientAuth) {
		wrapExceptions(() -> {
			doAddAuthExtension(certBuilder, serverAuth, clientAuth);
			return null;
		});
	}

	private static void doAddAuthExtension(final X509v3CertificateBuilder certBuilder, final boolean serverAuth, final boolean clientAuth) throws IOException {
		if (serverAuth || clientAuth) {
			final List<KeyPurposeId> keyPurposeIds = new ArrayList<>(2);
			if (serverAuth) {
				keyPurposeIds.add(KeyPurposeId.id_kp_serverAuth);
			}
			if (clientAuth) {
				keyPurposeIds.add(KeyPurposeId.id_kp_clientAuth);
			}

			final Extension extension = new Extension(
					Extension.extendedKeyUsage,
					true,
					new ExtendedKeyUsage(keyPurposeIds.toArray(KeyPurposeId[]::new)).getEncoded());

			certBuilder.addExtension(extension);
		}
	}

	static KeyPair generateRSAKeyPair(final int keySize) {
		return wrapExceptions(() -> doGenerateRSAKeyPair(keySize));
	}

	private static KeyPair doGenerateRSAKeyPair(final int keySize) throws NoSuchAlgorithmException, NoSuchProviderException {
		final KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
		kpGen.initialize(keySize, secureRandom());
		return kpGen.generateKeyPair();
	}

	static X509CertificateHolder generateV1Certificate(final KeyPair keyPair, final X500Name issuerAndSubject, final BigInteger serial, final int days) {
		return wrapExceptions(() -> doGenerateV1Certificate(keyPair, issuerAndSubject, serial, days));
	}

	private static X509CertificateHolder doGenerateV1Certificate(final KeyPair keyPair, final X500Name issuerAndSubject, final BigInteger serial, final int days) throws OperatorCreationException {
		final Date notBefore = new Date();
		final Date notAfter = Date.from(ZonedDateTime.now().plusDays(days).toInstant());

		final SubjectPublicKeyInfo subjectPublicKeyInfo = subjectPublicKeyInfo(keyPair.getPublic());

		final ContentSigner contentSigner = contentSigner(keyPair.getPrivate());

		return new X509v1CertificateBuilder(issuerAndSubject, serial, notBefore, notAfter, issuerAndSubject, subjectPublicKeyInfo)
				.build(contentSigner);
	}

	private static SubjectPublicKeyInfo subjectPublicKeyInfo(final PublicKey publicKey) {
		final byte[] pk = publicKey.getEncoded();
		return SubjectPublicKeyInfo.getInstance(pk);
	}

	static ContentSigner contentSigner(final PrivateKey privateKey) {
		return wrapExceptions(() -> contentSigner(privateKey, "SHA256"));
	}

	private static ContentSigner contentSigner(final PrivateKey signatureKey, final String hashAlgorithm) throws OperatorCreationException {
		final String keyAlgo = signatureKey.getAlgorithm();
		String signatureAlgorithm;
		if ("EC".equalsIgnoreCase(keyAlgo)) {
			signatureAlgorithm = hashAlgorithm + "WITHECDSA";
		} else {
			signatureAlgorithm = hashAlgorithm + "WITH" + keyAlgo;
		}
		return new JcaContentSignerBuilder(signatureAlgorithm).build(signatureKey);
	}

	static X509Certificate toJcaCertificate(final X509CertificateHolder cert) {
		return wrapExceptions(() -> new JcaX509CertificateConverter().getCertificate(cert));
	}

	static X509v3CertificateBuilder baseCertBuilder(@Nullable final X509CertificateHolder rootCert, final KeyPair keyPair,
			final X500Name subject, final BigInteger serial, final int days) {
		return wrapExceptions(() -> doBaseCertBuilder(rootCert, keyPair, subject, serial, days));
	}

	private static X509v3CertificateBuilder doBaseCertBuilder(@Nullable final X509CertificateHolder rootCert, final KeyPair keyPair,
			final X500Name subject, final BigInteger serial, final int days)
					throws NoSuchAlgorithmException, CertIOException {

		final Date notBefore = new Date();
		final Date notAfter = Date.from(ZonedDateTime.now().plusDays(days).toInstant());

		final X500Name issuer;
		if (rootCert == null) {
			issuer = subject;
		} else {
			issuer = rootCert.getSubject();
		}

		final SubjectPublicKeyInfo subjectPublicKeyInfo = subjectPublicKeyInfo(keyPair.getPublic());

		final X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(issuer, serial, notBefore, notAfter, subject, subjectPublicKeyInfo);

		final X509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

		if (rootCert != null) {
			certBuilder
			.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(rootCert));
		}

		certBuilder
		.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(subjectPublicKeyInfo))
		.addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
		.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

		return certBuilder;
	}

	private static <V> V wrapExceptions(final Callable<V> c) {
		try {
			return c.call();
		} catch (final Exception e) {
			throw new CertificateBuildException(e);
		}
	}
}