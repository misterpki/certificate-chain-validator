package com.misterpki;

import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CertificateChainValidatorTest {

  @Test
  public void validateCertificateChainSuccess() throws FileNotFoundException, CertificateException {
    final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    final File file = new File("src/test/resources/ca-cert.pem");
    final FileInputStream fileInputStream = new FileInputStream(file);
    final X509Certificate x509Certificate = (X509Certificate) certificateFactory.generateCertificate(fileInputStream);
    assertTrue(CertificateChainValidator.validateCertificateChain(Collections.singletonList(x509Certificate)));
  }

  @Test
  public void validateCertificateChainFail() throws FileNotFoundException, CertificateException {
    final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

    final File file = new File("src/test/resources/ca-cert.pem");
    final FileInputStream fileInputStream = new FileInputStream(file);
    final X509Certificate x509Certificate = (X509Certificate) certificateFactory.generateCertificate(fileInputStream);

    final File file2 = new File("src/test/resources/ca-cert2.pem");
    final FileInputStream fileInputStream2 = new FileInputStream(file2);
    final X509Certificate x509Certificate2 = (X509Certificate) certificateFactory.generateCertificate(fileInputStream2);

    assertFalse(CertificateChainValidator.validateCertificateChain(Arrays.asList(x509Certificate, x509Certificate2)));
  }
}