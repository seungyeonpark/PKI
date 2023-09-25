package pki.common.entity;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import pki.common.util.KeyUtil;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class RootCaIssuer extends Issuer {

    public RootCaIssuer() {
        super.issuerName = new X500Name("CN=Private Root CA, O=Certification Authority, L=Seoul, C=KR");
        super.issuerKeyPair = KeyUtil.generateRSAKeyPair();
        super.subjectValidity = 50;
        super.signatureAlg = "SHA256WithRSA";
        super.signatureAlgId = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption);
        super.policyOid = "2.5.29.32.0";
    }

    public List<Extension> getSelfExtensionList(AuthorityKeyIdentifier aki, SubjectPublicKeyInfo ski) throws IOException {
        List<Extension> extensionList = new ArrayList<>();

        // 1. authority key identifier
        Extension authorityKeyIdentifier = Extension.create(Extension.authorityKeyIdentifier, false, aki);
        extensionList.add(authorityKeyIdentifier);

        // 2. subject key identifier
        Extension subjectKeyIdentifier = Extension.create(Extension.subjectKeyIdentifier, false, ski);
        extensionList.add(subjectKeyIdentifier);

        // 3. key usage
        KeyUsage ku = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.digitalSignature);
        Extension keyUsage = Extension.create(Extension.keyUsage, true, ku);
        extensionList.add(keyUsage);

        // 4. basic constraints
        BasicConstraints bc = new BasicConstraints(1);
        Extension basicConstraints = Extension.create(Extension.basicConstraints, true, bc);
        extensionList.add(basicConstraints);

        return extensionList;
    }

    @Override
    public List<Extension> getSubjectExtensionList(AuthorityKeyIdentifier aki, SubjectPublicKeyInfo ski) throws IOException {
        List<Extension> extensionList = new ArrayList<>();

        // 1. authority key identifier
        Extension authorityKeyIdentifier = Extension.create(Extension.authorityKeyIdentifier, false, aki);
        extensionList.add(authorityKeyIdentifier);

        // 2. subject key identifier
        Extension subjectKeyIdentifier = Extension.create(Extension.subjectKeyIdentifier, false, ski);
        extensionList.add(subjectKeyIdentifier);

        // 3. certificate policy
        CertificatePolicies cp = new CertificatePolicies(new PolicyInformation(new ASN1ObjectIdentifier(policyOid)));
        Extension certificatePolicy = Extension.create(Extension.certificatePolicies, true, cp);
        extensionList.add(certificatePolicy);

        // 4. key usage
        KeyUsage ku = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.digitalSignature);
        Extension keyUsage = Extension.create(Extension.keyUsage, true, ku);
        extensionList.add(keyUsage);

        // 5. basic constraints
        BasicConstraints bc = new BasicConstraints(Integer.MAX_VALUE);
        Extension basicConstraints = Extension.create(Extension.basicConstraints, true, bc);
        extensionList.add(basicConstraints);

        return extensionList;
    }
}
