package javapqcoauthjwtsaml;

public class NegativeCases {
    public String parseBearerToken(String header) {
        return header.replace("Bearer ", "");
    }
}
