package pki.common.entity;

import lombok.Getter;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;

import java.io.IOException;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

@Getter
public abstract class Issuer {

    protected X500Name issuerName;

    protected KeyPair issuerKeyPair;

    protected int subjectValidity;

    protected String signatureAlg;

    protected AlgorithmIdentifier signatureAlgId;

    protected String policyOid;

    public List<Extension> getSubjectExtensionList(AuthorityKeyIdentifier aki, SubjectPublicKeyInfo ski) throws IOException {
        List<Extension> extensionList = new ArrayList<>();

        // 1. authority key identifier
        Extension authorityKeyIdentifier = Extension.create(Extension.authorityKeyIdentifier, false, aki);
        extensionList.add(authorityKeyIdentifier);

        // 2. subject key identifier
        Extension subjectKeyIdentifier = Extension.create(Extension.subjectKeyIdentifier, false, ski);
        extensionList.add(subjectKeyIdentifier);

        return extensionList;
    }
}
