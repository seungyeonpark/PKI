package pki.certificate;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import pki.common.entity.Issuer;
import pki.common.entity.RootCaIssuer;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

public class BaseCertificate {

    public static X509Certificate getCertificate(Issuer issuer, byte[] certificateRequestInfo) throws IOException, OperatorCreationException, CertificateException, NoSuchAlgorithmException, InvalidKeySpecException {
        Security.addProvider(new BouncyCastleProvider());

        /* 0. Extract Key Info */
        AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier(SubjectPublicKeyInfo.getInstance(issuer.getIssuerKeyPair().getPublic().getEncoded()).getEncoded());

        PKCS10CertificationRequest pkcs10CertificationRequest = new PKCS10CertificationRequest(certificateRequestInfo);
        SubjectPublicKeyInfo subjectPublicKeyInfo = pkcs10CertificationRequest.getSubjectPublicKeyInfo();
        SubjectKeyIdentifier ski = new SubjectKeyIdentifier(subjectPublicKeyInfo.getEncoded());
        String subjectPubKeyAlg = new DefaultAlgorithmNameFinder().getAlgorithmName(new ASN1ObjectIdentifier(subjectPublicKeyInfo.getAlgorithm().getAlgorithm().getId()));
        PublicKey subjectPublicKey = KeyFactory.getInstance(subjectPubKeyAlg).generatePublic(new X509EncodedKeySpec(subjectPublicKeyInfo.getEncoded()));

        /* 1. Basic Fields */
        // 1-1. serial number
        BigInteger serialNumber = BigInteger.valueOf((new SecureRandom().nextLong() & Long.MAX_VALUE) % Long.MAX_VALUE);

        // 1-2. issuer
        X500Name issuerName = issuer.getIssuerName();

        // 1-3. subject
        X500Name subjectName = pkcs10CertificationRequest.getSubject();

        // 1-4. startDate, endDate
        int validity = issuer.getSubjectValidity();
        if (issuerName.equals(subjectName)) {
            validity = ((RootCaIssuer) issuer).getSelfValidity();
        }

        long currentTimeMillis = System.currentTimeMillis();
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date(currentTimeMillis));
        calendar.add(Calendar.YEAR, validity);

        Date startDate = new Date(currentTimeMillis);
        Date endDate = new Date(calendar.getTimeInMillis());

        /* 2. Certificate Signing Info */
        ContentSigner contentSigner = new JcaContentSignerBuilder(issuer.getSignatureAlg()).setProvider("BC").build(issuer.getIssuerKeyPair().getPrivate());

        /* 3. Extension Fields */
        List<Extension> extensionList = issuer.getSubjectExtensionList(aki, ski);
        if (issuerName.equals(subjectName)) {
            extensionList = ((RootCaIssuer) issuer).getSelfExtensionList(aki, ski);
        }

        /* 4. X509Certificate */
        // 4-1. certificate builder
        JcaX509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                issuerName,
                serialNumber,
                startDate,
                endDate,
                subjectName,
                subjectPublicKey
        );

        for (Extension extension : extensionList) {
            certificateBuilder.addExtension(extension);
        }

        // 4-2. certificate holder
        X509CertificateHolder certificateHolder = certificateBuilder.build(contentSigner);

        // 4-3. certificate
        X509Certificate certificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificateHolder);

        return certificate;
    }
}
