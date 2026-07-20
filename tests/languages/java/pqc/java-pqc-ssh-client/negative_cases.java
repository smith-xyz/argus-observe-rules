package javapqcsshclient;

public class NegativeCases {
    public String formatSshCommand(String host, String user) {
        return "ssh " + user + "@" + host;
    }
}
