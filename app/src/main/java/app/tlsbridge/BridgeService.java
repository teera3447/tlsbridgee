package app.tlsbridge;

import android.app.Notification;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;

import java.io.IOException;

/** Foreground service: starts the TLS engine, the local proxy and (with root) the port 80 redirect. */
public class BridgeService extends Service {
    static volatile boolean running;
    static volatile ProxyServer proxy;

    private Thread worker;
    private boolean redirectRequested;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        startForegroundCompat();
        synchronized (this) {
            if (worker == null || !worker.isAlive()) {
                worker = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        runBridge();
                    }
                }, "tlsbridge-worker");
                worker.start();
            }
        }
        return START_STICKY; // the system restarts us after a kill (intent will be null)
    }

    private void runBridge() {
        Prefs prefs = new Prefs(this);
        int port = prefs.port();
        try {
            TlsEngine tls = TlsEngine.get(this);
            ProxyServer server = new ProxyServer(port, prefs.upgrade(), prefs.fallback(), tls);
            server.start();
            proxy = server;
            running = true;
            LogBuffer.add("Bridge listening on 127.0.0.1:" + port
                    + " (upgrade=" + prefs.upgrade() + ", fallback=" + prefs.fallback() + ")");
        } catch (IOException e) {
            LogBuffer.add("Cannot listen on port " + port + ": " + e.getMessage());
            stopSelf();
            return;
        } catch (Throwable t) {
            LogBuffer.add("Bridge failed to start: " + t);
            stopSelf();
            return;
        }

        if (prefs.transparent()) {
            redirectRequested = true;
            applyRedirectWithRetry(port);
        }
    }

    /** Right after boot the su daemon may not answer yet, so retry for about a minute. */
    private void applyRedirectWithRetry(int port) {
        for (int attempt = 1; attempt <= 6 && running; attempt++) {
            if (Iptables.apply(port)) return;
            try {
                Thread.sleep(10000);
            } catch (InterruptedException e) {
                return;
            }
        }
        LogBuffer.add("Redirect not applied: root unavailable or iptables unsupported. Bridge still works as a manual HTTP proxy.");
    }

    @Override
    public void onDestroy() {
        running = false;
        ProxyServer p = proxy;
        proxy = null;
        if (p != null) p.stop();
        if (worker != null) worker.interrupt();
        if (redirectRequested) {
            // never leave a redirect pointing at a dead port
            new Thread(new Runnable() {
                @Override
                public void run() {
                    Iptables.remove();
                }
            }, "tlsbridge-cleanup").start();
        }
        LogBuffer.add("Bridge stopped");
        super.onDestroy();
    }

    private void startForegroundCompat() {
        PendingIntent pi = PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class),
                Build.VERSION.SDK_INT >= 23 ? PendingIntent.FLAG_IMMUTABLE : 0);
        Notification n;
        if (Build.VERSION.SDK_INT >= 26) {
            n = Api26.notification(this, pi);
        } else {
            Notification.Builder b = new Notification.Builder(this)
                    .setContentTitle("TLS Bridge")
                    .setContentText("HTTP -> HTTPS (TLS 1.3) bridge is running")
                    .setSmallIcon(android.R.drawable.ic_lock_lock)
                    .setContentIntent(pi)
                    .setOngoing(true);
            n = Build.VERSION.SDK_INT >= 16 ? b.build() : b.getNotification();
        }
        startForeground(1, n);
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
