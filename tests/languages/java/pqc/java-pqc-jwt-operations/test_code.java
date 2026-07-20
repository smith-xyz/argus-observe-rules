package javapqcjwtoperations;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Claims;

public class TestCode {
    public String createToken(Claims claims, java.security.Key key) {
        return Jwts.builder()
            .setClaims(claims)
            .signWith(key)
            .compact();
    }

    public Claims parseToken(String token, java.security.Key key) {
        return Jwts.parser()
            .setSigningKey(key)
            .parseClaimsJws(token)
            .getBody();
    }

    public Claims parseWithBuilder(String token, java.security.Key key) {
        return Jwts.parserBuilder()
            .setSigningKey(key)
            .build()
            .parseClaimsJws(token)
            .getBody();
    }

    public Object parseJwt(String token) {
        return Jwts.parser().parse(token);
    }
}
