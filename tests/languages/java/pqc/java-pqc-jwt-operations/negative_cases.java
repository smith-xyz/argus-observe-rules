package javapqcjwtoperations;

public class NegativeCases {
    public String buildTokenString(String header, String payload) {
        return header + "." + payload + ".sig";
    }

    public boolean validateFormat(String token) {
        return token.split("\.").length == 3;
    }
}
