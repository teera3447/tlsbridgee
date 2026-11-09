package app.tlsbridge;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.LinkedList;
import java.util.Locale;

/** In-memory ring buffer of log lines shown in the UI (also forwarded to logcat). */
final class LogBuffer {
    private static final int MAX_LINES = 400;
    private static final LinkedList<String> LINES = new LinkedList<String>();
    private static final SimpleDateFormat FORMAT = new SimpleDateFormat("HH:mm:ss", Locale.US);

    private LogBuffer() { }

    static synchronized void add(String message) {
        LINES.add(FORMAT.format(new Date()) + "  " + message);
        while (LINES.size() > MAX_LINES) {
            LINES.removeFirst();
        }
        android.util.Log.i("TlsBridge", message);
    }

    static synchronized String tail(int count) {
        StringBuilder sb = new StringBuilder();
        int skip = Math.max(0, LINES.size() - count);
        int i = 0;
        for (String line : LINES) {
            if (i++ < skip) continue;
            sb.append(line).append('\n');
        }
        return sb.toString();
    }

    static synchronized void clear() {
        LINES.clear();
    }
}
