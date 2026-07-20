package javapqcellipticcurves;

import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.security.Signature;

public class TestCode {
    public void genEcKey() throws Exception {
        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
        ec.initialize(new ECGenParameterSpec("secp256r1"));
        ec.initialize(new ECGenParameterSpec("secp384r1"));
        ec.initialize(new ECGenParameterSpec("secp521r1"));
    }

    public void genEdKeys() throws Exception {
        KeyPairGenerator ed25519 = KeyPairGenerator.getInstance("Ed25519");
        KeyPairGenerator ed448 = KeyPairGenerator.getInstance("Ed448");
    }

    public byte[] signData(Signature signature, byte[] data) throws Exception {
        signature.update(data);
        return signature.sign();
    }
}
