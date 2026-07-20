package javapqcpkiinfrastructure;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPath;
import java.security.cert.PKIXParameters;

public class TestCode {
    public X509Certificate loadCert(InputStream stream) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) factory.generateCertificate(stream);
    }

    public void verifyCert(X509Certificate cert, java.security.PublicKey issuerKey) throws Exception {
        cert.getPublicKey();
        cert.verify(issuerKey);
    }

    public void validatePath(CertPath path, PKIXParameters params) throws Exception {
        CertPathValidator validator = CertPathValidator.getInstance("PKIX");
        validator.validate(path, params);
    }
}
