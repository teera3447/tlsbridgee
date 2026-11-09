package app.tlsbridge;

import android.content.Context;
import android.content.SharedPreferences;

/** Small wrapper around SharedPreferences with the app's defaults. */
final class Prefs {
    static final String AUTOSTART = "autostart";
    static final String TRANSPARENT = "transparent";
    static final String UPGRADE = "upgrade";
    static final String FALLBACK = "fallback";
    private static final String PORT = "port";
    private static final String FIRST_RUN_DONE = "first_run_done";

    private final SharedPreferences sp;

    Prefs(Context context) {
        sp = context.getApplicationContext().getSharedPreferences("tlsbridge", Context.MODE_PRIVATE);
    }

    boolean autostart() { return sp.getBoolean(AUTOSTART, true); }

    /** Redirect all plain HTTP (port 80) traffic of the device to the bridge (needs root). */
    boolean transparent() { return sp.getBoolean(TRANSPARENT, true); }

    /** Fetch http:// URLs over https:// (TLS 1.3 / 1.2) first. */
    boolean upgrade() { return sp.getBoolean(UPGRADE, true); }

    /** If the HTTPS attempt fails, serve the original http:// request instead. */
    boolean fallback() { return sp.getBoolean(FALLBACK, true); }

    int port() { return sp.getInt(PORT, 8118); }

    boolean firstRunDone() { return sp.getBoolean(FIRST_RUN_DONE, false); }

    void markFirstRunDone() { sp.edit().putBoolean(FIRST_RUN_DONE, true).commit(); }

    void setBool(String key, boolean value) { sp.edit().putBoolean(key, value).commit(); }
}
