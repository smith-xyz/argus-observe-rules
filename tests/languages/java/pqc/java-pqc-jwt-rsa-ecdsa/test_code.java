package javapqcjwtrsaecdsa;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class TestCode {
    public String signRs256(java.security.Key key) {
        return Jwts.builder()
            .setSubject("user")
            .signWith(key, SignatureAlgorithm.RS256)
            .compact();
    }

    public String signEs256(java.security.Key key) {
        return Jwts.builder()
            .setSubject("user")
            .signWith(key, SignatureAlgorithm.ES256)
            .compact();
    }

    public void listAlgorithms() {
        SignatureAlgorithm rs384 = SignatureAlgorithm.RS384;
        SignatureAlgorithm es512 = SignatureAlgorithm.ES512;
        SignatureAlgorithm ps256 = SignatureAlgorithm.PS256;
    }
}
