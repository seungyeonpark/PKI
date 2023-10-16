# X.509 Public Key Infrastructure Certificate

## 1. Project
### 1-1. Structure
``` bash
├── pki
│   ├── certificate
│   │   ├── BaseCertificate.java
│   │   └── CustomCertificate.java
│   ├── common
│   │   └── entity
│   │      ├── CaIssuer.java
│   │      ├── Issuer.java
│   │      └── RootCaIssuer.java
│   │   └── util
│   │      ├── FileUtil.java
│   │      └── KeyUtil.java
│   ├── csr
│   │   └── CsrManager.java
│   ├── validation
│   │   └── PathValidator.java
└────── CertificateApplication.java
```

### 1-2. Scenario (issuing certificate)
1. Applicant generates a key pair
2. Applicant generates a PKCS#10 structure. It mainly includes the subject information, public key generated in the above step
3. The applicant signs the PKCS#10 using the private key generated in the above step.
4. CA receives the PKCS#10
5. CA first verifies the PKCS#10 signature with the public key placed in the PKCS#10. If the signature is verified successfully then it is a proof that the applicant has a possession of the corresponding private key.
6. CA sends the final issued certificate along with the certificate chain to the applicant.

## 2. RFC5280
### 2-1. Certificate and Certificate Extensions Profile
1. Basic Certificate Fields
   1. Certificate Fields
      1. tbsCertificate
      2. signatureAlgorithm
      3. signatureValue
   2. TBSCertificate
      1. Version
      2. Serial Number
      3. Signature
      4. Issuer
      5. Validity
      6. Subject
      7. Subject Public Key Info
      8. Unique Identifiers
      9. Extensions
2. Certificate Extensions
   1. Authority Key Identifiers
   2. Subject Key Identifiers
   3. Key Usage
   4. Certificate Policies
   5. Policy Mappings
   6. Subject Alternative Name
   7. Issuer Alternative Name
   8. Subject Directory Attributes
   9. Basic Constraints
   10. Name Constraints
   11. Policy Constraints
   12. Extended Key Usage
   13. CRL Distribution Points
   14. Inhibit anyPolicy
   15. Freshest CRL

### 2-2. Certificate Path Validation
1. Basic Path Validation
   1. Inputs
   2. Initialization
   3. Basic Certificate Processing
   4. Preparation for Certificate i+1
   5. Wrap-Up Procedure
   6. Outputs
2. Using the Path Validation Algorithm
3. CRL Validation

## 3. PKCS#10 CSR
1. A CertificationRequestInfo value containing a subject distinguished name, a subject public key, and optionally a set of attributes is constructed by an entity requesting certification.
2. The CertificationRequestInfo value is signed with the subject entity's private key.
3. The CertificationRequestInfo value, a signature algorithm identifier, and the entity's signature are collected together into a CertificationRequest value

