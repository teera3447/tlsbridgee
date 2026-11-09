package app.tlsbridge;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Typeface;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;

import okhttp3.Request;
import okhttp3.Response;

/** Single-screen UI built in code (no layout XML, works on API 14+). */
public class MainActivity extends Activity {
    private static final String CHECK_URL_HTTPS = "https://www.howsmyssl.com/a/check";
    private static final String CHECK_URL_HTTP = "http://www.howsmyssl.com/a/check";

    private final Handler handler = new Handler(Looper.getMainLooper());
    private Prefs prefs;
    private TextView statusView;
    private TextView logView;
    private volatile String rootState = "ยังไม่ได้ตรวจ";

    private final Runnable ticker = new Runnable() {
        @Override
        public void run() {
            refresh();
            handler.postDelayed(this, 1000);
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        prefs = new Prefs(this);

        ScrollView scroll = new ScrollView(this);
        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        int pad = dp(16);
        col.setPadding(pad, pad, pad, pad);
        scroll.addView(col);

        TextView title = new TextView(this);
        title.setText("TLS Bridge");
        title.setTextSize(24);
        col.addView(title);

        statusView = new TextView(this);
        statusView.setPadding(0, dp(8), 0, dp(8));
        col.addView(statusView);

        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.addView(button("เริ่มบริการ", new Runnable() {
            @Override
            public void run() {
                startBridge();
            }
        }), weight());
        row.addView(button("หยุดบริการ", new Runnable() {
            @Override
            public void run() {
                stopBridge();
            }
        }), weight());
        col.addView(row);

        col.addView(check("เริ่มอัตโนมัติเมื่อเปิดเครื่อง", Prefs.AUTOSTART, prefs.autostart()));
        col.addView(check("ใช้ root เปลี่ยนเส้นทางทราฟฟิก HTTP (พอร์ต 80) ของทุกแอปมาที่บริดจ์",
                Prefs.TRANSPARENT, prefs.transparent()));
        col.addView(check("อัปเกรด http:// เป็น https:// (TLS 1.3 / 1.2) ก่อนเสมอ", Prefs.UPGRADE, prefs.upgrade()));
        col.addView(check("ถอยกลับไปใช้ HTTP เดิมเมื่อเว็บไม่รองรับ HTTPS", Prefs.FALLBACK, prefs.fallback()));

        col.addView(button("ตรวจสอบ root", new Runnable() {
            @Override
            public void run() {
                checkRoot();
            }
        }));
        col.addView(button("ทดสอบ TLS (ตรงจากแอป)", new Runnable() {
            @Override
            public void run() {
                testDirect();
            }
        }));
        col.addView(button("ทดสอบผ่านบริดจ์ (http -> https)", new Runnable() {
            @Override
            public void run() {
                testBridge();
            }
        }));
        col.addView(button("ลบกฎ iptables ทันที", new Runnable() {
            @Override
            public void run() {
                bg(new Runnable() {
                    @Override
                    public void run() {
                        Iptables.remove();
                    }
                });
            }
        }));
        col.addView(button("ล้างบันทึก", new Runnable() {
            @Override
            public void run() {
                LogBuffer.clear();
            }
        }));

        logView = new TextView(this);
        logView.setTypeface(Typeface.MONOSPACE);
        logView.setTextSize(11);
        logView.setPadding(0, dp(8), 0, 0);
        col.addView(logView);

        setContentView(scroll);

        // Prepare the TLS stack in the background so the status line can show the protocols.
        bg(new Runnable() {
            @Override
            public void run() {
                try {
                    TlsEngine.get(MainActivity.this);
                } catch (Throwable t) {
                    LogBuffer.add("TLS init failed: " + t);
                }
            }
        });

        // Android only delivers BOOT_COMPLETED after the app has been opened once.
        if (!prefs.firstRunDone()) {
            prefs.markFirstRunDone();
            if (prefs.autostart()) startBridge();
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        handler.post(ticker);
    }

    @Override
    protected void onPause() {
        handler.removeCallbacks(ticker);
        super.onPause();
    }

    // ------------------------------------------------------------ actions

    private void startBridge() {
        startService(new Intent(this, BridgeService.class));
    }

    private void stopBridge() {
        stopService(new Intent(this, BridgeService.class));
    }

    private void restartIfRunning() {
        if (!BridgeService.running) return;
        stopBridge();
        handler.postDelayed(new Runnable() {
            @Override
            public void run() {
                startBridge();
            }
        }, 1500);
    }

    private void checkRoot() {
        rootState = "กำลังตรวจ... (กดอนุญาตในแอปจัดการ root)";
        bg(new Runnable() {
            @Override
            public void run() {
                StringBuilder detail = new StringBuilder();
                boolean ok = RootShell.isRootAvailable(detail);
                rootState = ok ? "ใช้งานได้" : "ไม่มี root หรือถูกปฏิเสธ";
                LogBuffer.add("Root check: " + (ok ? "OK " : "FAILED ") + detail);
            }
        });
    }

    private void testDirect() {
        bg(new Runnable() {
            @Override
            public void run() {
                try {
                    TlsEngine engine = TlsEngine.get(MainActivity.this);
                    Request request = new Request.Builder().url(CHECK_URL_HTTPS).build();
                    Response response = engine.client.newCall(request).execute();
                    try {
                        LogBuffer.add("Direct test: " + summarize(response.body().string()));
                    } finally {
                        response.close();
                    }
                } catch (Throwable t) {
                    LogBuffer.add("Direct test failed: " + t);
                }
            }
        });
    }

    private void testBridge() {
        bg(new Runnable() {
            @Override
            public void run() {
                try {
                    Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", prefs.port()));
                    HttpURLConnection c = (HttpURLConnection) new URL(CHECK_URL_HTTP).openConnection(proxy);
                    c.setConnectTimeout(10000);
                    c.setReadTimeout(20000);
                    int code = c.getResponseCode();
                    InputStream in = code >= 400 ? c.getErrorStream() : c.getInputStream();
                    ByteArrayOutputStream buf = new ByteArrayOutputStream();
                    byte[] chunk = new byte[4096];
                    int n;
                    while (in != null && (n = in.read(chunk)) != -1) {
                        buf.write(chunk, 0, n);
                    }
                    LogBuffer.add("Bridge test (http:// request, HTTP " + code + "): "
                            + summarize(buf.toString("UTF-8")));
                } catch (Throwable t) {
                    LogBuffer.add("Bridge test failed (is the service running?): " + t);
                }
            }
        });
    }

    private static String summarize(String json) {
        try {
            JSONObject j = new JSONObject(json);
            return "tls_version=" + j.optString("tls_version") + ", rating=" + j.optString("rating");
        } catch (Exception e) {
            return json.length() > 160 ? json.substring(0, 160) : json;
        }
    }

    // ------------------------------------------------------------ UI helpers

    private void refresh() {
        TlsEngine engine = TlsEngine.peek();
        ProxyServer proxy = BridgeService.proxy;
        StringBuilder s = new StringBuilder();
        s.append("บริการ: ").append(BridgeService.running ? "กำลังทำงาน" : "หยุดอยู่").append('\n');
        s.append("Root: ").append(rootState).append('\n');
        s.append("TLS: ").append(engine == null ? "กำลังเตรียม..." : engine.summary);
        if (proxy != null && BridgeService.running) {
            s.append("\nบริดจ์: 127.0.0.1:").append(proxy.port()).append('\n').append(proxy.stats());
        }
        statusView.setText(s.toString());
        logView.setText(LogBuffer.tail(80));
    }

    private CheckBox check(String label, final String key, boolean value) {
        CheckBox box = new CheckBox(this);
        box.setText(label);
        box.setChecked(value);
        box.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton button, boolean checked) {
                prefs.setBool(key, checked);
                if (!Prefs.AUTOSTART.equals(key)) restartIfRunning();
            }
        });
        return box;
    }

    private Button button(String label, final Runnable action) {
        Button b = new Button(this);
        b.setText(label);
        b.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                action.run();
            }
        });
        return b;
    }

    private static LinearLayout.LayoutParams weight() {
        return new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
    }

    private static void bg(Runnable r) {
        new Thread(r).start();
    }

    private int dp(int v) {
        return (int) (v * getResources().getDisplayMetrics().density + 0.5f);
    }
}
