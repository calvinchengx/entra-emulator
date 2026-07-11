// Real-MSAL4J e2e suite (com.microsoft.azure:msal4j) against a running emulator
// (via e2e/run.sh). Client credentials → app-only token.
// Env: EMU_ORIGIN, EMU_TENANT, EMU_CERT.
import com.microsoft.aad.msal4j.ClientCredentialFactory;
import com.microsoft.aad.msal4j.ClientCredentialParameters;
import com.microsoft.aad.msal4j.ConfidentialClientApplication;
import com.microsoft.aad.msal4j.IAuthenticationResult;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collections;

public class Suite {
    static int failures = 0;

    static void check(String name, boolean cond, String extra) {
        System.out.println(cond ? "  ok  " + name : "  FAIL " + name + " " + extra);
        if (!cond) failures++;
    }

    public static void main(String[] args) throws Exception {
        String origin = System.getenv("EMU_ORIGIN");
        String tenant = System.getenv("EMU_TENANT");
        String authority = origin + "/" + tenant + "/";     // msal4j wants a trailing slash
        String daemonId = "cccccccc-0000-0000-0000-000000000002";
        String daemonSecret = "daemon-app-secret";

        trustEmulatorCert(System.getenv("EMU_CERT"));
        System.out.println("MSAL4J flows against " + authority);

        // AAD-style authority + instance discovery off, exactly like the other
        // SDKs: msal4j treats the emulator as a normal tenant.
        ConfidentialClientApplication app = ConfidentialClientApplication.builder(
                        daemonId, ClientCredentialFactory.createFromSecret(daemonSecret))
                .authority(authority)
                .validateAuthority(false)
                .instanceDiscovery(false)
                .build();

        IAuthenticationResult result = app.acquireToken(
                ClientCredentialParameters
                        .builder(Collections.singleton("api://" + daemonId + "/.default"))
                        .build())
                .get();

        check("client_credentials: token acquired",
                result.accessToken() != null && !result.accessToken().isEmpty(), "");

        String payload = new String(Base64.getUrlDecoder().decode(result.accessToken().split("\\.")[1]));
        check("client_credentials: aud + roles",
                payload.contains("\"aud\":\"api://" + daemonId + "\"") && payload.contains("Tasks.Read.All"),
                payload);
        check("client_credentials: no scp/oid",
                !payload.contains("\"scp\"") && !payload.contains("\"oid\""), payload);

        System.out.println(failures == 0 ? "PASS" : "FAIL (" + failures + ")");
        System.exit(failures == 0 ? 0 : 1);
    }

    // Load the emulator's self-signed cert into a fresh trust store and make it
    // the JVM default, so msal4j's HTTP client accepts the TLS connection.
    static void trustEmulatorCert(String certPath) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate ca;
        try (FileInputStream in = new FileInputStream(certPath)) {
            ca = (X509Certificate) cf.generateCertificate(in);
        }
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        ks.setCertificateEntry("emulator", ca);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, tmf.getTrustManagers(), null);
        SSLContext.setDefault(ctx);
        HttpsURLConnection.setDefaultSSLSocketFactory(ctx.getSocketFactory());
    }
}
