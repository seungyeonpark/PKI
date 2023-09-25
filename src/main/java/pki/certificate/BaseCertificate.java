package pki.certificate;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
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
import java.util.Calendar;
import java.util.Date;
import java.util.List;

public class BaseCertificate {

    public X509Certificate getCertificate(Issuer issuer, byte[] certificateRequestInfo) throws IOException, OperatorCreationException, CertificateException {
        Security.addProvider(new BouncyCastleProvider());
        PKCS10CertificationRequest pkcs10CertificationRequest = new PKCS10CertificationRequest(certificateRequestInfo);

        // 1. Basic Fields

        // 1-1. serial number
        BigInteger serialNumber = BigInteger.valueOf((new SecureRandom().nextLong() & Long.MAX_VALUE) % Long.MAX_VALUE);

        // 1-2. issuer
        X500Name issuerName = issuer.getIssuerName();

        // 1-3. subject
        X500Name subjectName = pkcs10CertificationRequest.getSubject();

        // 1-4. startDate, endDate
        long currentTimeMillis = System.currentTimeMillis();
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date(currentTimeMillis));
        calendar.add(Calendar.YEAR, issuer.getSubjectValidity());

        Date startDate = new Date(currentTimeMillis);
        Date endDate = new Date(calendar.getTimeInMillis());

        // 2. Certificate Signing Info
        ContentSigner contentSigner = new JcaContentSignerBuilder(issuer.getSignatureAlg()).setProvider("BC").build(issuer.getIssuerKeyPair().getPrivate());

        // 3. Extension Fields
        AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier(SubjectPublicKeyInfo.getInstance(issuer.getIssuerKeyPair().getPublic().getEncoded()).getEncoded());
        SubjectPublicKeyInfo ski = pkcs10CertificationRequest.getSubjectPublicKeyInfo();

        List<Extension> extensionList = issuer.getSubjectExtensionList(aki, ski);
        if (issuerName.equals(subjectName)) {
            extensionList = ((RootCaIssuer) issuer).getSelfExtensionList(aki, ski);
        }

        // 4. X509Certificate

        // 4-1. certificate builder
        JcaX509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                issuerName,
                serialNumber,
                startDate,
                endDate,
                subjectName,
                issuer.getIssuerKeyPair().getPublic()
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
