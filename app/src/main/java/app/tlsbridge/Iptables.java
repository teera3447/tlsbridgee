package app.tlsbridge;

/**
 * Transparent redirect of all outgoing TCP port 80 traffic (except our own app and loopback)
 * to the local bridge, using a dedicated nat chain so it can be removed cleanly.
 * Rules are not persistent: a reboot clears them (the boot receiver re-applies them).
 */
final class Iptables {
    private static final String CHAIN = "TLSBRIDGE";
    private static final String NAT = "iptables -t nat ";

    private Iptables() { }

    static boolean apply(int port) {
        int uid = android.os.Process.myUid();
        String cmd = NAT + "-N " + CHAIN + " 2>/dev/null; "
                + NAT + "-F " + CHAIN + " && "
                + NAT + "-A " + CHAIN + " ! -d 127.0.0.0/8 -m owner ! --uid-owner " + uid
                + " -j REDIRECT --to-ports " + port + " && { "
                + NAT + "-D OUTPUT -p tcp --dport 80 -j " + CHAIN + " 2>/dev/null; "
                + NAT + "-I OUTPUT 1 -p tcp --dport 80 -j " + CHAIN + "; }";
        RootShell.Result r = RootShell.run(20000, cmd);
        if (r.ok()) {
            LogBuffer.add("iptables: port 80 -> 127.0.0.1:" + port + " redirect active (uid " + uid + " excluded)");
            return true;
        }
        LogBuffer.add("iptables apply failed (code " + r.code + "): " + (r.err.length() > 0 ? r.err : r.out));
        return false;
    }

    static void remove() {
        String cmd = NAT + "-D OUTPUT -p tcp --dport 80 -j " + CHAIN + " 2>/dev/null; "
                + NAT + "-F " + CHAIN + " 2>/dev/null; "
                + NAT + "-X " + CHAIN + " 2>/dev/null; true";
        RootShell.Result r = RootShell.run(20000, cmd);
        LogBuffer.add(r.ok() ? "iptables: redirect rules removed" : "iptables remove failed: " + r.err);
    }

    static boolean isActive() {
        RootShell.Result r = RootShell.run(20000, NAT + "-L OUTPUT -n");
        return r.ok() && r.out.contains(CHAIN);
    }
}
