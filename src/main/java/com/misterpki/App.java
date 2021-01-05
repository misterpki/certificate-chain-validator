package com.misterpki;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class App {

  public static void main(final String[] args) throws CertificateException, FileNotFoundException {
    final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    final List<X509Certificate> x509CertificateList = new ArrayList<>();
    for (final String fileName : args) {
      x509CertificateList.add((X509Certificate) certificateFactory.generateCertificate(new FileInputStream(fileName)));
    }

    if (CertificateChainValidator.validateCertificateChain(x509CertificateList)) {
      System.out.println("Valid");
    } else {
      System.out.println("Invalid");
    }
  }
}