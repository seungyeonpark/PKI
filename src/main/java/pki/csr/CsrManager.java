package pki.csr;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import pki.common.Constants;
import pki.common.KeyUtil;

import java.io.*;
import java.security.*;

public class CsrManager {

    public void generateCsr() throws OperatorCreationException, IOException {
        X500Name subjectName = new X500Name(Constants.subjectDN);
        KeyPair subjectKeyPair = KeyUtil.generateRSAKeyPair();
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(subjectKeyPair.getPublic().getEncoded());

        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(Constants.csrSigningAlg);
        ContentSigner signer = signerBuilder.build(subjectKeyPair.getPrivate());

        PKCS10CertificationRequestBuilder csrBuilder = new PKCS10CertificationRequestBuilder(subjectName, subjectPublicKeyInfo);
        PKCS10CertificationRequest csr = csrBuilder.build(signer);

        FileOutputStream fo = new FileOutputStream(Constants.csrFilePath);
        fo.write(csr.getEncoded());
        fo.close();
    }
}
