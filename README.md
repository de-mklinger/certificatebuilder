certificatebuilder
====

Simple Builder API for X.509 certificates using Bouncy Castle.

Usage
--

Maven dependency:

```xml
<dependency>
    <groupId>de.mklinger.commons</groupId>
    <artifactId>certificatebuilder</artifactId>
    <version>1.0</version>
</dependency>
```

Create a self-signed server certificate:

```java
CertificateAndKeyPair certificateAndKeyPair = new CertificateBuilder()
    .subjectCn("selfsigned-cert")
    .subjectO("My Organization")
    .serverAuth(true)
    .dnsSan("example.org")
    .ipSan("127.0.0.1")
    .validDays(365)
    .keySize(2048)
    .build();
```

Create CA root certificate, intermediated certificate and signed certificate:

```java
CertificateAndKeyPair root = new CertificateBuilder()
    .subjectCn("ca-root")
    .build();

CertificateAndKeyPair intermediate = new CertificateBuilder()
    .subjectCn("ca-intermediate")
    .validDays(365)
    .issuer(root)
    .build();

CertificateAndKeyPair cert = new CertificateBuilder()
    .subjectCn("cert")
    .validDays(365)
    .issuer(intermediate)
    .serverAuth(true)
    .dnsSan("example.org")
    .ipSan("127.0.0.1")
    .build();

PrivateKey privateKey = certificateAndKeyPair.getKeyPair().getPrivate();

Certificate[] certificateChain = {
    cert.getCertificate(),
    intermediate.getCertificate(),
    root.getCertificate()
};
```
