package pki.certificate;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import pki.common.Constants;

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

public class ManualSignCertificate {

    public X509Certificate getCertificate(byte[] certificateRequestInfo) throws IOException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, CertificateException {

        // 1. tobeSignedData
        TBSCertificate tbsCertificate = getTBSCertificate(certificateRequestInfo);
        byte[] tobeSignedData = tbsCertificate.toASN1Primitive().getEncoded();

        // 2. signatureValue
        byte[] signatureValue = getSignatureValue(tobeSignedData);

        // 3. certificate
        X509Certificate x509Certificate = getX509Certificate(tbsCertificate, Constants.signatureAlgId, signatureValue);

        return x509Certificate;
    }

    private TBSCertificate getTBSCertificate(byte[] certificateRequestInfo) throws IOException {

        /** 1. Process CSR message **/
        PKCS10CertificationRequest pkcs10CertificationRequest = new PKCS10CertificationRequest(certificateRequestInfo);
        SubjectPublicKeyInfo subjectPublicKeyInfo = pkcs10CertificationRequest.getSubjectPublicKeyInfo();

        /** 2. Generate TBSCertificate **/
        V3TBSCertificateGenerator tbsGen = new V3TBSCertificateGenerator();

        // 2-1. serial number
        long serialNumber = (new SecureRandom().nextLong() & Long.MAX_VALUE) % Long.MAX_VALUE;
        tbsGen.setSerialNumber(new ASN1Integer(new BigInteger(String.valueOf(serialNumber))));

        // 2-2. issuer
        tbsGen.setIssuer(new X500Name(Constants.issuerDN));

        // 2-3. startDate, endDate
        Time startDate = new Time(new Date(System.currentTimeMillis()));
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date(System.currentTimeMillis()));
        calendar.add(Calendar.YEAR, Constants.validity);
        Time endDate = new Time(new Date(calendar.getTimeInMillis()));

        tbsGen.setStartDate(startDate);
        tbsGen.setEndDate(endDate);

        // 2-4. subject
        tbsGen.setSubject(pkcs10CertificationRequest.getSubject());

        // 2-5. subjectPublicKeyInfo
        tbsGen.setSubjectPublicKeyInfo(subjectPublicKeyInfo);

        // 2-6. signature
        tbsGen.setSignature(Constants.signatureAlgId);

        // 2-7. extension values
        ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();

        // 2-8. authority key identifier
        AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier(SubjectPublicKeyInfo.getInstance(Constants.issuerKeyPair.getPublic().getEncoded()).getEncoded());
        Extension authorityKeyIdentifier = Extension.create(Extension.authorityKeyIdentifier, false, aki);
        extensionsGenerator.addExtension(authorityKeyIdentifier);

        // 2-9. subject key identifier
        SubjectPublicKeyInfo ski = pkcs10CertificationRequest.getSubjectPublicKeyInfo();
        Extension subjectKeyIdentifier = Extension.create(Extension.subjectKeyIdentifier, false, ski);
        extensionsGenerator.addExtension(subjectKeyIdentifier);

        // 2-10. certificate policy
        CertificatePolicies cp = new CertificatePolicies(new PolicyInformation(new ASN1ObjectIdentifier(Constants.policyOid)));
        Extension certificatePolicy = Extension.create(Extension.certificatePolicies, true, cp);
        extensionsGenerator.addExtension(certificatePolicy);

        // 2-11. key usage
        KeyUsage ku = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation);
        Extension keyUsage = Extension.create(Extension.keyUsage, true, ku);
        extensionsGenerator.addExtension(keyUsage);

        // 2-12. basic constraints
        BasicConstraints bc = new BasicConstraints(false);
        Extension basicConstraints = Extension.create(Extension.basicConstraints, true, bc);
        extensionsGenerator.addExtension(basicConstraints);

        tbsGen.setExtensions(extensionsGenerator.generate());

        /** 3. Generate TBSCertificate **/
        return tbsGen.generateTBSCertificate();
    }

    private static byte[] getSignatureValue(byte[] tobeSignedData) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(Constants.signatureAlg);
        signature.initSign(Constants.issuerKeyPair.getPrivate());
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
