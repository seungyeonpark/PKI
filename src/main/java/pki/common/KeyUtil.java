package pki.common;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECGenParameterSpec;

public class KeyUtil {

    public static KeyPair generateRSAKeyPair() {
        KeyPairGenerator keyPairGenerator = null;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    public static KeyPair generateECKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(ecSpec);
        return keyPairGenerator.generateKeyPair();
    }

}
