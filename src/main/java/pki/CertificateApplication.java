package pki;

import org.bouncycastle.operator.OperatorCreationException;
import pki.certificate.BaseCertificate;
import pki.common.entity.CaIssuer;
import pki.common.entity.RootCaIssuer;
import pki.common.util.FileUtil;
import pki.common.util.KeyUtil;
import pki.csr.CsrManager;
import pki.validation.PathValidator;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;

public class CertificateApplication {

	public static final String csrSigningAlg = "SHA256WithRSA";

	public static final String rootCaDn = "CN=Private Root CA, OU=Private Certificate Authority, O=Private Corp., C=KR";
	public static final String caDn = "CN=Private CA, OU=Private Certificate Authority, O=Private Corp., C=KR";
	public static final String userDn = "CN=sypark, O=Certification Authority, L=Seoul, C=KR";

	public static final String rootCaCertPath = "\\Users\\User\\Desktop\\Project\\pki\\src\\main\\resources\\certificates\\root.cer";
	public static final String caCertPath = "\\Users\\User\\Desktop\\Project\\pki\\src\\main\\resources\\certificates\\ca.cer";
	public static final String userCertPath = "\\Users\\User\\Desktop\\Project\\pki\\src\\main\\resources\\certificates\\user.cer";

	public static final String policyOid = "2.5.29.32.0"; // any policy

	public static void main(String[] args) throws IOException, OperatorCreationException, CertificateException, NoSuchAlgorithmException, InvalidKeySpecException, CertPathValidatorException, InvalidAlgorithmParameterException, NoSuchProviderException {

		// 1. Root CA Certificate
		RootCaIssuer rootCaIssuer = new RootCaIssuer(rootCaDn, policyOid);
		byte[] rootCaCsr = CsrManager.getCsr(rootCaIssuer.getIssuerKeyPair(), rootCaDn, csrSigningAlg);
		X509Certificate rootCaCertificate = BaseCertificate.getCertificate(rootCaIssuer, rootCaCsr);
		FileUtil.saveCertificate(rootCaCertPath, rootCaCertificate);


		// 2. CA Certificate
		CaIssuer caIssuer = new CaIssuer(caDn, policyOid);
		byte[] caCsr = CsrManager.getCsr(caIssuer.getIssuerKeyPair(), caDn, csrSigningAlg);
		X509Certificate caCertificate = BaseCertificate.getCertificate(rootCaIssuer, caCsr);
		FileUtil.saveCertificate(caCertPath, caCertificate);

		// 3. Leaf Certificate
		KeyPair userKeyPair = KeyUtil.generateRSAKeyPair();
		byte[] userCsr = CsrManager.getCsr(userKeyPair, userDn, csrSigningAlg);
		X509Certificate userCertificate = BaseCertificate.getCertificate(caIssuer, userCsr);
		FileUtil.saveCertificate(userCertPath, userCertificate);

		// 4. Path Validation
		PathValidator.validateCertPath(rootCaCertificate, caCertificate, userCertificate);

	}
}
