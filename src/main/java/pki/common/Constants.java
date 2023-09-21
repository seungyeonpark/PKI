package pki.common;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import java.security.KeyPair;

public abstract class Constants {

    /**
     * CSR
     */
    public static final String csrSigningAlg = "SHA256withRSA";

    public static final String subjectDN = "CN=Seungyeon Park, O=Certification Authority, L=Seoul, C=KR";

    public static final String csrFilePath = "C:\\Users\\User\\Desktop\\Project\\pki\\csr.pem";

    /**
     * Certificate
     */
    public static final int validity = 1; // year

    public static final String policyOid = "2.5.29.32.0"; // any policy

    public static final String issuerDN = "CN=Test CA, O=Certification Authority, L=Seoul, C=KR";

    public static final KeyPair issuerKeyPair = new KeyUtil().generateRSAKeyPair(); // RSA KeyPair

    public static final String signatureAlg = "SHA256WithRSA";

    public static final AlgorithmIdentifier signatureAlgId = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption); // SHA256WithRSA
}
