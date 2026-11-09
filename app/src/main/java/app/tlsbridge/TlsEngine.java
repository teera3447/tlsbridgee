package app.tlsbridge;

import android.content.Context;
import android.util.Base64;

import org.conscrypt.Conscrypt;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyStore;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import okhttp3.ConnectionPool;
import okhttp3.ConnectionSpec;
import okhttp3.OkHttpClient;
import okhttp3.Protocol;
import okhttp3.TlsVersion;

/**
 * Owns the modern TLS stack: the bundled Conscrypt (BoringSSL) provider, a trust manager that
 * validates against the bundled Mozilla CA list plus the system store, and the shared OkHttp client.
 * Certificate and hostname verification are always on.
 */
final class TlsEngine {
    private static TlsEngine instance;

    /** Shared client: TLS 1.3 / 1.2 only for https, pooled keep-alive connections. */
    final OkHttpClient client;
    /** Same pool, shorter connect timeout; used to probe whether a host speaks HTTPS. */
    final OkHttpClient probe;
    final String summary;

    static synchronized TlsEngine get(Context context) {
        if (instance == null) {
            instance = new TlsEngine(context.getApplicationContext());
        }
        return instance;
    }

    static synchronized TlsEngine peek() {
        return instance;
    }

    private TlsEngine(Context context) {
        Provider provider = null;
        try {
            if (Conscrypt.isAvailable()) {
                provider = Conscrypt.newProvider();
                Security.insertProviderAt(provider, 1);
                LogBuffer.add("Conscrypt (BoringSSL) provider installed");
            } else {
                LogBuffer.add("Conscrypt native library not available on this device (unsupported CPU ABI?)");
            }
        } catch (Throwable t) {
            provider = null;
            LogBuffer.add("Conscrypt init failed: " + t);
        }

        X509TrustManager trustManager = buildTrustManager(context, provider);

        SSLContext sslContext;
        try {
            sslContext = provider != null
                    ? SSLContext.getInstance("TLS", provider)
                    : SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[] { trustManager }, new SecureRandom());
        } catch (Exception e) {
            throw new IllegalStateException("Cannot create SSLContext", e);
        }

        String protocols = "?";
        try {
            protocols = Arrays.toString(sslContext.getSupportedSSLParameters().getProtocols());
        } catch (Throwable ignored) {
            // diagnostics only
        }
        summary = (provider != null ? "Conscrypt/BoringSSL" : "Platform TLS (no TLS 1.3)")
                + " protocols=" + protocols;
        LogBuffer.add("TLS: " + summary);

        ConnectionSpec modern = new ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
                .tlsVersions(TlsVersion.TLS_1_3, TlsVersion.TLS_1_2)
                .build();

        OkHttpClient base = new OkHttpClient.Builder()
                .sslSocketFactory(sslContext.getSocketFactory(), trustManager)
                .connectionSpecs(Arrays.asList(modern, ConnectionSpec.CLEARTEXT))
                .protocols(Collections.singletonList(Protocol.HTTP_1_1))
                .followRedirects(false)
                .followSslRedirects(false)
                .retryOnConnectionFailure(true)
                .connectTimeout(10, TimeUnit.SECONDS)
                .readTimeout(30, TimeUnit.SECONDS)
                .writeTimeout(30, TimeUnit.SECONDS)
                .connectionPool(new ConnectionPool(16, 5, TimeUnit.MINUTES))
                .build();
        client = base;
        probe = base.newBuilder().connectTimeout(6, TimeUnit.SECONDS).build();
    }

    // ---------------------------------------------------------------- trust

    private static X509TrustManager buildTrustManager(Context context, Provider provider) {
        List<X509TrustManager> managers = new ArrayList<X509TrustManager>();

        try {
            KeyStore bundled = loadBundledCa(context);
            if (bundled != null) {
                TrustManagerFactory tmf;
                try {
                    tmf = provider != null
                            ? TrustManagerFactory.getInstance("PKIX", provider)
                            : TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                } catch (Exception e) {
                    tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                }
                tmf.init(bundled);
                addFirstX509(managers, tmf);
            }
        } catch (Throwable t) {
            LogBuffer.add("Bundled CA list could not be used: " + t);
        }

        try {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init((KeyStore) null);
            addFirstX509(managers, tmf);
        } catch (Throwable t) {
            LogBuffer.add("System trust store unavailable: " + t);
        }

        if (managers.isEmpty()) {
            throw new IllegalStateException("No trust manager available");
        }
        return managers.size() == 1 ? managers.get(0) : new CompositeTrustManager(managers);
    }

    private static void addFirstX509(List<X509TrustManager> out, TrustManagerFactory tmf) {
        for (TrustManager tm : tmf.getTrustManagers()) {
            if (tm instanceof X509TrustManager) {
                out.add((X509TrustManager) tm);
                return;
            }
        }
    }

    /** Parses assets/cacert.pem (Mozilla bundle from curl.se) into an in-memory KeyStore. */
    private static KeyStore loadBundledCa(Context context) throws Exception {
        InputStream in;
        try {
            in = context.getAssets().open("cacert.pem");
        } catch (IOException e) {
            LogBuffer.add("assets/cacert.pem missing - using the device's own CA store only");
            return null;
        }
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(in, "US-ASCII"));
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
            store.load(null, null);
            StringBuilder block = null;
            int loaded = 0;
            int skipped = 0;
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("-----BEGIN CERTIFICATE-----")) {
                    block = new StringBuilder();
                } else if (line.startsWith("-----END CERTIFICATE-----")) {
                    if (block != null) {
                        try {
                            byte[] der = Base64.decode(block.toString(), Base64.DEFAULT);
                            X509Certificate cert = (X509Certificate) factory.generateCertificate(
                                    new ByteArrayInputStream(der));
                            store.setCertificateEntry("ca" + loaded, cert);
                            loaded++;
                        } catch (Exception e) {
                            skipped++;
                        }
                    }
                    block = null;
                } else if (block != null) {
                    block.append(line.trim()).append('\n');
                }
            }
            LogBuffer.add("Bundled CA list: " + loaded + " certificates loaded"
                    + (skipped > 0 ? ", " + skipped + " skipped" : ""));
            return loaded > 0 ? store : null;
        } finally {
            try {
                in.close();
            } catch (IOException ignored) {
                // nothing to do
            }
        }
    }

    /** Accepts a chain if any of the wrapped managers accepts it. Never accepts blindly. */
    private static final class CompositeTrustManager implements X509TrustManager {
        private final List<X509TrustManager> managers;

        CompositeTrustManager(List<X509TrustManager> managers) {
            this.managers = managers;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            managers.get(0).checkClientTrusted(chain, authType);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            CertificateException last = null;
            for (X509TrustManager tm : managers) {
                try {
                    tm.checkServerTrusted(chain, authType);
                    return;
                } catch (CertificateException e) {
                    last = e;
                }
            }
            throw last != null ? last : new CertificateException("No trust managers");
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            List<X509Certificate> all = new ArrayList<X509Certificate>();
            for (X509TrustManager tm : managers) {
                all.addAll(Arrays.asList(tm.getAcceptedIssuers()));
            }
            return all.toArray(new X509Certificate[all.size()]);
        }
    }
}
