package javapqcmessagesigning;

import java.security.Signature;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSASigner;

public class TestCode {
    public void rsaSign(byte[] data) throws Exception {
        Signature sha256rsa = Signature.getInstance("SHA256withRSA");
        Signature sha384rsa = Signature.getInstance("SHA384withRSA");
        Signature sha512rsa = Signature.getInstance("SHA512withRSA");
        sha256rsa.update(data);
        sha256rsa.sign();
    }

    public void ecSign(byte[] data) throws Exception {
        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        Signature ed25519 = Signature.getInstance("Ed25519");
        ecdsa.update(data);
        ecdsa.sign();
    }

    public void jwsSign(java.security.interfaces.RSAPrivateKey key) throws Exception {
        JWSObject jws = new JWSObject(new JWSHeader(com.nimbusds.jose.JWSAlgorithm.RS256), new Payload("data"));
        jws.sign(new RSASSASigner(key));
    }
}
