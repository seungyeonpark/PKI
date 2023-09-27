package pki.validation;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.*;
import java.util.*;

public class PathValidator {

    public static void validateCertPath(X509Certificate rootCaCert, X509Certificate caCert, X509Certificate leafCert) throws CertificateException, NoSuchProviderException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, CertPathValidatorException {
        Security.addProvider(new BouncyCastleProvider());
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", "BC");

        // 1. CertPath
        List<Certificate> certList = new ArrayList<>();
        certList.add(caCert);
        certList.add(leafCert);

        CertPath certPath = certificateFactory.generateCertPath(certList);

        // 2. TrustAnchor
        Set<TrustAnchor> trustAnchorSet = Collections.singleton(new TrustAnchor(rootCaCert, null));

        // 3. PKIXParameters
        PKIXParameters pkix = new PKIXParameters(trustAnchorSet);
        pkix.setRevocationEnabled(false);

        // 4. Validate
        CertPathValidator certPathValidator = CertPathValidator.getInstance("PKIX", "BC");
        certPathValidator.validate(certPath, pkix);
    }
}
