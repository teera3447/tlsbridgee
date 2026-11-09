package app.tlsbridge;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Build;

/** Starts the bridge when the device boots (or after the app is updated). */
public class BootReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent == null || intent.getAction() == null) return;
        if (!new Prefs(context).autostart()) return;
        Intent service = new Intent(context, BridgeService.class);
        try {
            if (Build.VERSION.SDK_INT >= 26) {
                Api26.startForeground(context, service);
            } else {
                context.startService(service);
            }
        } catch (Exception e) {
            LogBuffer.add("Boot start failed: " + e);
        }
    }
}
