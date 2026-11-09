package app.tlsbridge;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import javax.net.ssl.SSLHandshakeException;

import okhttp3.Headers;
import okhttp3.HttpUrl;
import okhttp3.MediaType;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

/**
 * Local HTTP proxy on 127.0.0.1.
 *
 * Plain http:// requests (absolute-form from a configured proxy, or origin-form with a Host header
 * from the iptables redirect) are fetched over https:// with TLS 1.3/1.2 and handed back to the
 * old client as plain HTTP. CONNECT tunnels are passed through untouched (the client's own TLS).
 */
final class ProxyServer {
    private static final int MAX_BODY = 8 * 1024 * 1024;
    private static final long NO_HTTPS_TTL_MS = 10 * 60 * 1000L;

    final AtomicLong requests = new AtomicLong();
    final AtomicLong upgraded = new AtomicLong();
    final AtomicLong fallbacks = new AtomicLong();
    final AtomicLong tunnels = new AtomicLong();
    final AtomicLong errors = new AtomicLong();

    private final int port;
    private final boolean upgrade;
    private final boolean fallback;
    private final TlsEngine tls;
    private final ConcurrentHashMap<String, Long> noHttps = new ConcurrentHashMap<String, Long>();

    private volatile boolean running;
    private ServerSocket server;
    private ThreadPoolExecutor pool;

    ProxyServer(int port, boolean upgrade, boolean fallback, TlsEngine tls) {
        this.port = port;
        this.upgrade = upgrade;
        this.fallback = fallback;
        this.tls = tls;
    }

    int port() { return port; }

    String stats() {
        return "requests=" + requests.get() + "  https=" + upgraded.get() + "  http-fallback=" + fallbacks.get()
                + "  tunnels=" + tunnels.get() + "  errors=" + errors.get();
    }

    // ------------------------------------------------------------ lifecycle

    void start() throws IOException {
        ServerSocket ss = new ServerSocket();
        ss.setReuseAddress(true);
        ss.bind(new InetSocketAddress(InetAddress.getByAddress(new byte[] { 127, 0, 0, 1 }), port), 128);
        server = ss;
        pool = new ThreadPoolExecutor(4, 96, 60, TimeUnit.SECONDS, new SynchronousQueue<Runnable>());
        running = true;
        Thread acceptor = new Thread(new Runnable() {
            @Override
            public void run() {
                acceptLoop();
            }
        }, "tlsbridge-accept");
        acceptor.setDaemon(true);
        acceptor.start();
    }

    void stop() {
        running = false;
        try {
            if (server != null) server.close();
        } catch (IOException ignored) {
            // closing anyway
        }
        if (pool != null) pool.shutdownNow();
    }

    private void acceptLoop() {
        while (running) {
            try {
                final Socket socket = server.accept();
                try {
                    pool.execute(new Runnable() {
                        @Override
                        public void run() {
                            handle(socket);
                        }
                    });
                } catch (RejectedExecutionException e) {
                    closeQuietly(socket);
                }
            } catch (IOException e) {
                if (running) {
                    LogBuffer.add("accept error: " + e);
                    try {
                        Thread.sleep(50);
                    } catch (InterruptedException ignored) {
                        return;
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------ request

    private static final class Req {
        String method;
        String target;
        final List<String[]> headers = new ArrayList<String[]>();

        String header(String name) {
            for (String[] h : headers) {
                if (h[0].equalsIgnoreCase(name)) return h[1];
            }
            return null;
        }
    }

    private void handle(Socket client) {
        try {
            client.setSoTimeout(30000);
            client.setTcpNoDelay(true);
            InputStream in = new BufferedInputStream(client.getInputStream(), 16384);
            OutputStream out = client.getOutputStream();
            Req req = readRequest(in);
            if (req == null) return;
            requests.incrementAndGet();
            if ("CONNECT".equalsIgnoreCase(req.method)) {
                tunnel(client, in, out, req);
            } else {
                forward(req, in, out);
            }
        } catch (Throwable ignored) {
            // client went away or sent garbage; upstream failures are counted where they happen
        } finally {
            closeQuietly(client);
        }
    }

    private static Req readRequest(InputStream in) throws IOException {
        String first = readLine(in);
        while (first != null && first.length() == 0) {
            first = readLine(in); // tolerate stray blank lines between requests
        }
        if (first == null) return null;
        String[] parts = first.split(" ");
        if (parts.length < 2) return null;
        Req r = new Req();
        r.method = parts[0];
        r.target = parts[1];
        int total = first.length();
        String line;
        while ((line = readLine(in)) != null && line.length() > 0) {
            total += line.length();
            if (total > 65536) throw new IOException("request headers too large");
            int colon = line.indexOf(':');
            if (colon > 0) {
                r.headers.add(new String[] { line.substring(0, colon).trim(), line.substring(colon + 1).trim() });
            }
        }
        return r;
    }

    private static String readLine(InputStream in) throws IOException {
        StringBuilder sb = new StringBuilder();
        int c;
        while ((c = in.read()) != -1) {
            if (c == '\n') {
                int n = sb.length();
                if (n > 0 && sb.charAt(n - 1) == '\r') sb.setLength(n - 1);
                return sb.toString();
            }
            sb.append((char) c);
            if (sb.length() > 16384) throw new IOException("line too long");
        }
        return sb.length() == 0 ? null : sb.toString();
    }

    private static byte[] readFully(InputStream in, int length) throws IOException {
        byte[] data = new byte[length];
        int off = 0;
        while (off < length) {
            int n = in.read(data, off, length - off);
            if (n < 0) throw new EOFException("client closed while sending body");
            off += n;
        }
        return data;
    }

    // ------------------------------------------------------------ forward

    private void forward(Req r, InputStream in, OutputStream out) throws IOException {
        HttpUrl clientUrl = clientUrl(r);
        if (clientUrl == null) {
            sendText(out, 400, "Bad Request", "Cannot determine the target URL");
            return;
        }
        String host = clientUrl.host();
        if (isLoopback(host)) {
            if (clientUrl.port() == port && "/".equals(clientUrl.encodedPath())) {
                sendHtml(out, "<html><body><h3>TLS Bridge is running</h3><p>" + tls.summary
                        + "</p><p>" + stats() + "</p></body></html>");
            } else {
                sendText(out, 403, "Forbidden", "Loopback targets are not proxied");
            }
            return;
        }

        String method = r.method.toUpperCase(Locale.US);

        String transferEncoding = r.header("Transfer-Encoding");
        if (transferEncoding != null && transferEncoding.toLowerCase(Locale.US).contains("chunked")) {
            sendText(out, 411, "Length Required", "Chunked request bodies are not supported");
            return;
        }
        byte[] body = null;
        String contentLength = r.header("Content-Length");
        if (contentLength != null) {
            int n;
            try {
                n = Integer.parseInt(contentLength.trim());
            } catch (NumberFormatException e) {
                sendText(out, 400, "Bad Request", "Bad Content-Length");
                return;
            }
            if (n < 0 || n > MAX_BODY) {
                sendText(out, 413, "Payload Too Large", "Request body too large");
                return;
            }
            String expect = r.header("Expect");
            if (n > 0 && expect != null && expect.toLowerCase(Locale.US).contains("100-continue")) {
                out.write("HTTP/1.1 100 Continue\r\n\r\n".getBytes("ISO-8859-1"));
                out.flush();
            }
            body = readFully(in, n);
        }

        Headers headers;
        RequestBody requestBody = null;
        try {
            Headers.Builder hb = new Headers.Builder();
            for (String[] h : r.headers) {
                if (isHopByHop(h[0]) || "Host".equalsIgnoreCase(h[0]) || "Content-Length".equalsIgnoreCase(h[0])) {
                    continue;
                }
                try {
                    hb.add(h[0], h[1]);
                } catch (IllegalArgumentException ignored) {
                    // header with characters OkHttp refuses: drop it
                }
            }
            headers = hb.build();
            if (!"GET".equals(method) && !"HEAD".equals(method) && (body != null || requiresBody(method))) {
                String contentType = r.header("Content-Type");
                MediaType mediaType = contentType != null ? MediaType.parse(contentType) : null;
                requestBody = RequestBody.create(mediaType, body != null ? body : new byte[0]);
            }
        } catch (IllegalArgumentException e) {
            sendText(out, 400, "Bad Request", "Malformed request");
            return;
        }

        Response response = null;
        boolean viaHttps = "https".equals(clientUrl.scheme());

        boolean tryUpgrade = upgrade && "http".equals(clientUrl.scheme()) && clientUrl.port() == 80
                && shouldUpgrade(host) && !knownNoHttps(host);
        if (tryUpgrade) {
            try {
                HttpUrl httpsUrl = clientUrl.newBuilder().scheme("https").port(443).build();
                response = tls.probe.newCall(build(httpsUrl, method, headers, requestBody)).execute();
                viaHttps = true;
                upgraded.incrementAndGet();
            } catch (IOException e) {
                boolean allowed = fallback && canFallback(method, e);
                LogBuffer.add("HTTPS failed for " + host + ": " + describe(e)
                        + (allowed ? " -> using plain HTTP" : ""));
                if (!allowed) {
                    errors.incrementAndGet();
                    sendText(out, 502, "Bad Gateway", "HTTPS request failed: " + describe(e));
                    return;
                }
                rememberNoHttps(host);
                fallbacks.incrementAndGet();
            } catch (IllegalArgumentException e) {
                sendText(out, 400, "Bad Request", "Malformed request");
                return;
            }
        }
        if (response == null) {
            try {
                response = tls.client.newCall(build(clientUrl, method, headers, requestBody)).execute();
            } catch (IOException e) {
                errors.incrementAndGet();
                LogBuffer.add("Upstream failed for " + host + ": " + describe(e));
                sendText(out, 502, "Bad Gateway", "Upstream request failed: " + describe(e));
                return;
            } catch (IllegalArgumentException e) {
                sendText(out, 400, "Bad Request", "Malformed request");
                return;
            }
        }

        try {
            writeResponse(out, method, response, clientUrl, viaHttps && "http".equals(clientUrl.scheme()));
        } finally {
            response.close();
        }
    }

    private static Request build(HttpUrl url, String method, Headers headers, RequestBody body) {
        return new Request.Builder().url(url).headers(headers).method(method, body).build();
    }

    private void writeResponse(OutputStream out, String method, Response response, HttpUrl clientUrl,
                               boolean upgradedFromHttp) throws IOException {
        int code = response.code();
        StringBuilder head = new StringBuilder(512);
        head.append("HTTP/1.1 ").append(code).append(' ').append(reason(code, response.message())).append("\r\n");
        Headers rh = response.headers();
        for (int i = 0; i < rh.size(); i++) {
            String name = rh.name(i);
            String value = rh.value(i);
            if (isHopByHop(name)) continue;
            if (upgrade && "http".equals(clientUrl.scheme())) {
                if ("Location".equalsIgnoreCase(name) && value.regionMatches(true, 0, "https://", 0, 8)) {
                    // keep the old client on http:// so its next request comes back through the bridge
                    value = "http://" + value.substring(8).replaceFirst("^([^/]*):443(?=/|$)", "$1");
                }
            }
            if (upgradedFromHttp && "Set-Cookie".equalsIgnoreCase(name)) {
                // a Secure cookie would be rejected by the client over plain http://
                value = value.replaceAll("(?i);\\s*secure(?=\\s*;|\\s*$)", "");
            }
            head.append(name).append(": ").append(value).append("\r\n");
        }
        head.append("Connection: close\r\n\r\n");

        BufferedOutputStream bo = new BufferedOutputStream(out, 16384);
        bo.write(head.toString().getBytes("ISO-8859-1"));
        boolean hasBody = !"HEAD".equals(method) && code != 204 && code != 304 && code >= 200;
        if (hasBody && response.body() != null) {
            InputStream body = response.body().byteStream();
            byte[] buffer = new byte[16384];
            int n;
            while ((n = body.read(buffer)) != -1) {
                bo.write(buffer, 0, n);
            }
        }
        bo.flush();
    }

    // ------------------------------------------------------------ CONNECT

    private void tunnel(final Socket client, InputStream clientIn, final OutputStream clientOut, Req r)
            throws IOException {
        String target = r.target;
        int colon = target.lastIndexOf(':');
        String host = colon > 0 ? target.substring(0, colon) : target;
        int targetPort = 443;
        if (colon > 0) {
            try {
                targetPort = Integer.parseInt(target.substring(colon + 1));
            } catch (NumberFormatException e) {
                sendText(clientOut, 400, "Bad Request", "Bad CONNECT target");
                return;
            }
        }
        if (host.startsWith("[") && host.endsWith("]")) {
            host = host.substring(1, host.length() - 1);
        }
        if (isLoopback(host)) {
            sendText(clientOut, 403, "Forbidden", "Loopback targets are not proxied");
            return;
        }

        final Socket remote = new Socket();
        try {
            remote.connect(new InetSocketAddress(host, targetPort), 10000);
        } catch (IOException e) {
            closeQuietly(remote);
            errors.incrementAndGet();
            sendText(clientOut, 502, "Bad Gateway", "Cannot connect to " + host + ":" + targetPort);
            return;
        }
        tunnels.incrementAndGet();
        remote.setTcpNoDelay(true);
        remote.setSoTimeout(300000);
        client.setSoTimeout(300000);
        clientOut.write("HTTP/1.1 200 Connection Established\r\n\r\n".getBytes("ISO-8859-1"));
        clientOut.flush();

        final InputStream remoteIn = remote.getInputStream();
        final OutputStream remoteOut = remote.getOutputStream();
        Thread down = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    pump(remoteIn, clientOut);
                } catch (IOException ignored) {
                    // tunnel ended
                }
                closeQuietly(client);
                closeQuietly(remote);
            }
        }, "tlsbridge-tunnel");
        down.setDaemon(true);
        down.start();
        try {
            pump(clientIn, remoteOut);
        } catch (IOException ignored) {
            // tunnel ended
        }
        closeQuietly(remote);
        closeQuietly(client);
    }

    private static void pump(InputStream in, OutputStream out) throws IOException {
        byte[] buffer = new byte[16384];
        int n;
        while ((n = in.read(buffer)) != -1) {
            out.write(buffer, 0, n);
            out.flush();
        }
    }

    // ------------------------------------------------------------ helpers

    private static HttpUrl clientUrl(Req r) {
        String t = r.target;
        String raw;
        if (t.regionMatches(true, 0, "http://", 0, 7) || t.regionMatches(true, 0, "https://", 0, 8)) {
            raw = t;
        } else if (t.startsWith("/")) {
            String host = r.header("Host");
            if (host == null || host.length() == 0) return null;
            raw = "http://" + host + t;
        } else {
            return null;
        }
        return HttpUrl.parse(raw);
    }

    private static boolean isLoopback(String host) {
        return "localhost".equalsIgnoreCase(host) || host.startsWith("127.") || "::1".equals(host)
                || "0.0.0.0".equals(host);
    }

    /** Skip the upgrade for IP literals, single-label and local names: they rarely have public certificates. */
    private static boolean shouldUpgrade(String host) {
        if (host.indexOf(':') >= 0) return false;
        if (host.matches("[0-9.]+")) return false;
        if (host.indexOf('.') < 0) return false;
        String h = host.toLowerCase(Locale.US);
        return !(h.endsWith(".local") || h.endsWith(".lan") || h.endsWith(".home") || h.endsWith(".internal"));
    }

    private static boolean requiresBody(String method) {
        return "POST".equals(method) || "PUT".equals(method) || "PATCH".equals(method)
                || "PROPPATCH".equals(method) || "REPORT".equals(method);
    }

    private static boolean canFallback(String method, IOException e) {
        if ("GET".equals(method) || "HEAD".equals(method) || "OPTIONS".equals(method)) return true;
        // never replay a request that may already have reached the server
        return e instanceof ConnectException || e instanceof UnknownHostException
                || e instanceof SSLHandshakeException;
    }

    private boolean knownNoHttps(String host) {
        Long since = noHttps.get(host);
        if (since == null) return false;
        if (System.currentTimeMillis() - since > NO_HTTPS_TTL_MS) {
            noHttps.remove(host);
            return false;
        }
        return true;
    }

    private void rememberNoHttps(String host) {
        if (noHttps.size() > 2000) noHttps.clear();
        noHttps.put(host, System.currentTimeMillis());
    }

    private static boolean isHopByHop(String name) {
        return "Connection".equalsIgnoreCase(name) || "Proxy-Connection".equalsIgnoreCase(name)
                || "Keep-Alive".equalsIgnoreCase(name) || "Proxy-Authenticate".equalsIgnoreCase(name)
                || "Proxy-Authorization".equalsIgnoreCase(name) || "TE".equalsIgnoreCase(name)
                || "Trailer".equalsIgnoreCase(name) || "Transfer-Encoding".equalsIgnoreCase(name)
                || "Upgrade".equalsIgnoreCase(name);
    }

    private static String describe(IOException e) {
        String msg = e.getMessage();
        String s = e.getClass().getSimpleName() + (msg != null ? ": " + msg : "");
        return s.length() > 140 ? s.substring(0, 140) : s;
    }

    private static String reason(int code, String message) {
        if (message != null && message.length() > 0) {
            return message.replace('\r', ' ').replace('\n', ' ');
        }
        switch (code) {
            case 200: return "OK";
            case 201: return "Created";
            case 204: return "No Content";
            case 206: return "Partial Content";
            case 301: return "Moved Permanently";
            case 302: return "Found";
            case 303: return "See Other";
            case 304: return "Not Modified";
            case 307: return "Temporary Redirect";
            case 308: return "Permanent Redirect";
            case 400: return "Bad Request";
            case 401: return "Unauthorized";
            case 403: return "Forbidden";
            case 404: return "Not Found";
            case 405: return "Method Not Allowed";
            case 429: return "Too Many Requests";
            case 500: return "Internal Server Error";
            case 502: return "Bad Gateway";
            case 503: return "Service Unavailable";
            case 504: return "Gateway Timeout";
            default: return "Status";
        }
    }

    private static void sendText(OutputStream out, int code, String reason, String text) throws IOException {
        byte[] body = (text + "\n").getBytes("UTF-8");
        String head = "HTTP/1.1 " + code + " " + reason + "\r\nContent-Type: text/plain; charset=utf-8\r\n"
                + "Content-Length: " + body.length + "\r\nConnection: close\r\n\r\n";
        out.write(head.getBytes("ISO-8859-1"));
        out.write(body);
        out.flush();
    }

    private static void sendHtml(OutputStream out, String html) throws IOException {
        byte[] body = html.getBytes("UTF-8");
        String head = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
                + "Content-Length: " + body.length + "\r\nConnection: close\r\n\r\n";
        out.write(head.getBytes("ISO-8859-1"));
        out.write(body);
        out.flush();
    }

    private static void closeQuietly(Socket s) {
        try {
            s.close();
        } catch (IOException ignored) {
            // already closed
        }
    }
}
