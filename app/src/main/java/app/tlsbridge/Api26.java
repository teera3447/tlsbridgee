package app.tlsbridge;

import android.annotation.TargetApi;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;

/** Kept in its own class so Android 4.x never loads the API 26 notification classes. */
@TargetApi(26)
final class Api26 {
    private static final String CHANNEL_ID = "bridge";

    private Api26() { }

    static Notification notification(Context context, PendingIntent intent) {
        NotificationManager nm = (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
        NotificationChannel channel = new NotificationChannel(CHANNEL_ID, "TLS Bridge",
                NotificationManager.IMPORTANCE_LOW);
        nm.createNotificationChannel(channel);
        return new Notification.Builder(context, CHANNEL_ID)
                .setContentTitle("TLS Bridge")
                .setContentText("HTTP -> HTTPS (TLS 1.3) bridge is running")
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .setContentIntent(intent)
                .setOngoing(true)
                .build();
    }

    static void startForeground(Context context, android.content.Intent service) {
        context.startForegroundService(service);
    }
}
