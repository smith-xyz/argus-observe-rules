package javapqcjwtrsaecdsa;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class NegativeCases {
    public String signHs256(java.security.Key key) {
        return Jwts.builder()
            .setSubject("user")
            .signWith(key, SignatureAlgorithm.HS256)
            .compact();
    }
}
