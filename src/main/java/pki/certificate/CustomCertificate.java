package pki.certificate;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import pki.common.entity.Issuer;
import pki.common.entity.RootCaIssuer;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

public class CustomCertificate {

    public X509Certificate getCertificate(Issuer issuer, byte[] certificateRequestInfo) throws IOException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, CertificateException {

        // 1. tobeSignedData
        TBSCertificate tbsCertificate = getTBSCertificate(issuer, certificateRequestInfo);
        byte[] tobeSignedData = tbsCertificate.toASN1Primitive().getEncoded();

        // 2. signatureValue
        byte[] signatureValue = getSignatureValue(issuer, tobeSignedData);

        // 3. certificate
        X509Certificate x509Certificate = getX509Certificate(tbsCertificate, issuer.getSignatureAlgId(), signatureValue);

        return x509Certificate;
    }

    private TBSCertificate getTBSCertificate(Issuer issuer, byte[] certificateRequestInfo) throws IOException {

        /* 1. Process CSR message */
        PKCS10CertificationRequest pkcs10CertificationRequest = new PKCS10CertificationRequest(certificateRequestInfo);
        SubjectPublicKeyInfo subjectPublicKeyInfo = pkcs10CertificationRequest.getSubjectPublicKeyInfo();

        /* 2. Generate TBSCertificate */
        V3TBSCertificateGenerator tbsGen = new V3TBSCertificateGenerator();

        // 2-1. serial number
        long serialNumber = (new SecureRandom().nextLong() & Long.MAX_VALUE) % Long.MAX_VALUE;
        tbsGen.setSerialNumber(new ASN1Integer(new BigInteger(String.valueOf(serialNumber))));

        // 2-2. issuer
        X500Name issuerName = issuer.getIssuerName();
        tbsGen.setIssuer(issuerName);

        // 2-3. startDate, endDate
        Time startDate = new Time(new Date(System.currentTimeMillis()));
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date(System.currentTimeMillis()));
        calendar.add(Calendar.YEAR, issuer.getSubjectValidity());
        Time endDate = new Time(new Date(calendar.getTimeInMillis()));

        tbsGen.setStartDate(startDate);
        tbsGen.setEndDate(endDate);

        // 2-4. subject
        X500Name subjectName = pkcs10CertificationRequest.getSubject();
        tbsGen.setSubject(subjectName);

        // 2-5. subjectPublicKeyInfo
        tbsGen.setSubjectPublicKeyInfo(subjectPublicKeyInfo);

        // 2-6. signature
        tbsGen.setSignature(issuer.getSignatureAlgId());

        // 2-7. extension values
        AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier(SubjectPublicKeyInfo.getInstance(issuer.getIssuerKeyPair().getPublic().getEncoded()).getEncoded());
        SubjectKeyIdentifier ski = new SubjectKeyIdentifier(subjectPublicKeyInfo.getEncoded());

        List<Extension> extensionList = issuer.getSubjectExtensionList(aki, ski);
        if (issuerName.equals(subjectName)) {
            extensionList = ((RootCaIssuer) issuer).getSelfExtensionList(aki, ski);
        }

        ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
        for (Extension extension : extensionList) {
            extensionsGenerator.addExtension(extension);
        }
        tbsGen.setExtensions(extensionsGenerator.generate());

        /* 3. TBSCertificate */
        return tbsGen.generateTBSCertificate();
    }

    private static byte[] getSignatureValue(Issuer issuer, byte[] tobeSignedData) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(issuer.getSignatureAlg());
        signature.initSign(issuer.getIssuerKeyPair().getPrivate());
        signature.update(tobeSignedData);
        byte[] signatureValue = signature.sign();
        return signatureValue;
    }

    private static X509Certificate getX509Certificate(TBSCertificate tbsCertificate, AlgorithmIdentifier signatureAlgId, byte[] signatureValue) throws CertificateException, IOException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", new BouncyCastleProvider());
        Certificate certificate = Certificate.getInstance(new DERSequence(generateStructure(tbsCertificate, signatureAlgId, signatureValue)));

        InputStream is = new ByteArrayInputStream(certificate.getEncoded());
        X509Certificate x509Certificate = (X509Certificate) certificateFactory.generateCertificate(is);
        is.close();

        return x509Certificate;
    }

    private static ASN1EncodableVector generateStructure(TBSCertificate tbsCertificate, AlgorithmIdentifier signatureAlgId, byte[] signatureValue) {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(tbsCertificate);
        v.add(signatureAlgId);
        v.add(new DERBitString(signatureValue));
        return v;
    }
}
