package de.mklinger.test.certs;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import de.mklinger.micro.keystores.KeyStores;

public class CertificateBuilderTest {
	@Rule
	public TemporaryFolder tmp = new TemporaryFolder();

	@Test
	public void testSelfSigned() throws IOException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
		final CertificateAndKeyPair certificateAndKeyPair = new CertificateBuilder()
				.subjectCn("test-javagenerated-ca")
				.validDays(365)
				.keySize(1024) // speed things up
				.build();

		final Path path = tmp.newFile().toPath();

		try (OutputStream out = Files.newOutputStream(path)) {
			KeyStores.storeAsPkcs12(
					out,
					"thepwd",
					certificateAndKeyPair.getKeyPair().getPrivate(),
					certificateAndKeyPair.getCertificate());
		}

		final KeyStore keyStore = KeyStores.load(path.toAbsolutePath().toString(), "thepwd");

		// ---- assertions:
		assertThat(keyStore, not(nullValue()));

		assertRSAPrivateCrtKey(keyStore, "thepwd");

		assertSubjects(keyStore,
				"CN=test-javagenerated-ca");

		assertIssuerChain(keyStore);
	}

	@Test
	public void testSelfSignedWithExtensions() throws IOException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
		final CertificateAndKeyPair certificateAndKeyPair = new CertificateBuilder()
				.subjectCn("test-javagenerated-ca")
				.validDays(365)
				.keySize(1024) // speed things up
				.ipSan("127.0.0.1")
				.clientAuth(true)
				.build();

		final Path path = tmp.newFile().toPath();

		try (OutputStream out = Files.newOutputStream(path)) {
			KeyStores.storeAsPkcs12(
					out,
					"thepwd",
					certificateAndKeyPair.getKeyPair().getPrivate(),
					certificateAndKeyPair.getCertificate());
		}

		final KeyStore keyStore = KeyStores.load(path.toAbsolutePath().toString(), "thepwd");

		// ---- assertions:
		assertThat(keyStore, not(nullValue()));

		assertRSAPrivateCrtKey(keyStore, "thepwd");

		assertSubjects(keyStore,
				"CN=test-javagenerated-ca");

		assertIssuerChain(keyStore);

		final X509Certificate x509Cert = getX509Certificate(keyStore, 0);
		assertClientAuth(x509Cert);
		assertIpSan(x509Cert, "127.0.0.1");
	}

	@Test
	public void testSigned() throws IOException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
		final CertificateAndKeyPair caCertificateAndKeyPair = new CertificateBuilder()
				.subjectCn("test-javagenerated-ca")
				.validDays(365)
				.keySize(1024) // speed things up
				.build();

		final CertificateAndKeyPair certificateAndKeyPair = new CertificateBuilder()
				.subjectCn("test-javagenerated-certificate")
				.validDays(365)
				.keySize(1024) // speed things up
				.issuer(caCertificateAndKeyPair)
				.build();

		final Path path = tmp.newFile().toPath();

		try (OutputStream out = Files.newOutputStream(path)) {
			KeyStores.storeAsPkcs12(
					out,
					"thepwd",
					certificateAndKeyPair.getKeyPair().getPrivate(),
					certificateAndKeyPair.getCertificate(),
					caCertificateAndKeyPair.getCertificate());
		}

		final KeyStore keyStore = KeyStores.load(path.toAbsolutePath().toString(), "thepwd");

		// ---- assertions:
		assertThat(keyStore, not(nullValue()));

		assertRSAPrivateCrtKey(keyStore, "thepwd");

		assertSubjects(keyStore,
				"CN=test-javagenerated-certificate",
				"CN=test-javagenerated-ca");

		assertIssuerChain(keyStore);
	}

	@Test
	public void testFullChain() throws IOException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
		final CertificateAndKeyPair caRootCertificateAndKeyPair = new CertificateBuilder()
				.subjectCn("test-javagenerated-ca-root")
				.validDays(365)
				.keySize(1024) // speed things up
				.build();

		final CertificateAndKeyPair caIntermediateCertificateAndKeyPair = new CertificateBuilder()
				.subjectCn("test-javagenerated-ca-intermediate")
				.validDays(365)
				.keySize(1024) // speed things up
				.issuer(caRootCertificateAndKeyPair)
				.build();

		final CertificateAndKeyPair certificateAndKeyPair = new CertificateBuilder()
				.subjectCn("test-javagenerated-certificate")
				.validDays(365)
				.keySize(1024) // speed things up
				.issuer(caIntermediateCertificateAndKeyPair)
				.serverAuth(true)
				.clientAuth(true)
				.ipSan("127.0.0.1")
				.dnsSan("mklinger.de")
				.build();

		final Path path = tmp.newFile().toPath();

		try (OutputStream out = Files.newOutputStream(path)) {
			KeyStores.storeAsPkcs12(
					out,
					"thepwd",
					certificateAndKeyPair.getKeyPair().getPrivate(),
					certificateAndKeyPair.getCertificate(),
					caIntermediateCertificateAndKeyPair.getCertificate(),
					caRootCertificateAndKeyPair.getCertificate());
		}

		final KeyStore keyStore = KeyStores.load(path.toAbsolutePath().toString(), "thepwd");

		// ---- assertions:
		assertThat(keyStore, not(nullValue()));

		assertRSAPrivateCrtKey(keyStore, "thepwd");

		assertSubjects(keyStore,
				"CN=test-javagenerated-certificate",
				"CN=test-javagenerated-ca-intermediate",
				"CN=test-javagenerated-ca-root");

		assertIssuerChain(keyStore);

		final X509Certificate x509Cert = getX509Certificate(keyStore, 0);
		assertServerAuth(x509Cert);
		assertClientAuth(x509Cert);
		assertIpSan(x509Cert, "127.0.0.1");
		assertDnsSan(x509Cert, "mklinger.de");
	}

	private void assertIssuerChain(final KeyStore keyStore) throws KeyStoreException {
		final int len = getCertificateChain(keyStore).length;

		for (int issuerIdx = 1; issuerIdx < len; issuerIdx++) {
			final int issuedIdx = issuerIdx - 1;
			final X509Certificate issuer = getX509Certificate(keyStore, issuerIdx);
			final X509Certificate issued = getX509Certificate(keyStore, issuedIdx);
			assertThat(issuer.getSubjectX500Principal(), is(issued.getIssuerX500Principal()));
		}

		if (len > 0) {
			final X509Certificate root = getX509Certificate(keyStore, len - 1);
			assertThat(root.getIssuerX500Principal(), equalTo(root.getSubjectX500Principal()));
		}
	}

	private void assertRSAPrivateCrtKey(final KeyStore keyStore, final String keyPassword) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
		final List<String> aliases = Collections.list(keyStore.aliases());
		assertThat(aliases, hasSize(1));
		final String alias = aliases.get(0);

		final Key key = keyStore.getKey(alias, keyPassword.toCharArray());
		assertThat(key, instanceOf(RSAPrivateCrtKey.class));
	}

	private void assertSubjects(final KeyStore keyStore, final String... subjects) throws KeyStoreException {
		for (int idx = 0; idx < subjects.length; idx++) {
			final X509Certificate x509Cert = getX509Certificate(keyStore, idx);
			assertThat(x509Cert.getSubjectX500Principal().getName(), equalTo(subjects[idx]));
		}
	}

	private X509Certificate getX509Certificate(final KeyStore keyStore, final int chainIdx) throws KeyStoreException {
		final Certificate[] certificateChain = getCertificateChain(keyStore);
		assertThat(certificateChain.length, greaterThanOrEqualTo(chainIdx + 1));

		final Certificate cert = certificateChain[chainIdx];
		assertThat(cert, instanceOf(X509Certificate.class));
		final X509Certificate x509Cert = (X509Certificate) cert;

		return x509Cert;
	}

	private Certificate[] getCertificateChain(final KeyStore keyStore) throws KeyStoreException {
		final List<String> aliases = Collections.list(keyStore.aliases());
		assertThat(aliases, hasSize(1));
		final String alias = aliases.get(0);

		final Certificate[] certificateChain = keyStore.getCertificateChain(alias);
		assertThat(certificateChain, not(nullValue()));
		return certificateChain;
	}

	private void assertServerAuth(final X509Certificate x509Cert) throws CertificateParsingException {
		assertThat(x509Cert.getExtendedKeyUsage(), hasItem(KeyPurposeId.id_kp_serverAuth.toString()));
	}

	private void assertClientAuth(final X509Certificate x509Cert) throws CertificateParsingException {
		assertThat(x509Cert.getExtendedKeyUsage(), hasItem(KeyPurposeId.id_kp_clientAuth.toString()));
	}

	private void assertIpSan(final X509Certificate x509Cert, final String expectedValue) throws CertificateParsingException {
		assertSan(x509Cert, GeneralName.iPAddress, expectedValue);
	}

	private void assertDnsSan(final X509Certificate x509Cert, final String expectedValue) throws CertificateParsingException {
		assertSan(x509Cert, GeneralName.dNSName, expectedValue);
	}

	private void assertSan(final X509Certificate x509Cert, final int expectedType, final String expectedValue) throws CertificateParsingException {
		for (final List<?> sanTuple : x509Cert.getSubjectAlternativeNames()) {
			final Object actualSanType = sanTuple.get(0);
			final Object actualSanValue = sanTuple.get(1);
			if (actualSanType.equals(expectedType) && actualSanValue.equals(expectedValue)) {
				return;
			}
		}
		fail("Missing expected SAN of type " + expectedType + " with value '" + expectedValue + "'");
	}
}
