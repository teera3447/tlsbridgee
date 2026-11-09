package app.tlsbridge;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

/** Runs commands in a root shell ("su"). Never throws: failures are returned as a Result. */
final class RootShell {

    static final class Result {
        final int code;
        final String out;
        final String err;

        Result(int code, String out, String err) {
            this.code = code;
            this.out = out;
            this.err = err;
        }

        boolean ok() { return code == 0; }
    }

    private RootShell() { }

    /** The exit code is the one of the last command, so put the important command last. */
    static Result run(long timeoutMs, String... commands) {
        Process process = null;
        try {
            process = Runtime.getRuntime().exec("su");
            final Process proc = process;
            DataOutputStream os = new DataOutputStream(process.getOutputStream());
            for (String command : commands) {
                os.writeBytes(command + "\n");
            }
            os.writeBytes("exit\n");
            os.flush();

            final StringBuilder out = new StringBuilder();
            final StringBuilder err = new StringBuilder();
            Thread outThread = drain(process.getInputStream(), out);
            Thread errThread = drain(process.getErrorStream(), err);

            final int[] code = { -1 };
            Thread waiter = new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        code[0] = proc.waitFor();
                    } catch (InterruptedException ignored) {
                        // timeout path below destroys the process
                    }
                }
            });
            waiter.setDaemon(true);
            waiter.start();
            waiter.join(timeoutMs);
            if (waiter.isAlive()) {
                process.destroy();
                waiter.interrupt();
                return new Result(-2, "", "timeout after " + timeoutMs + " ms (root prompt not answered?)");
            }
            outThread.join(1000);
            errThread.join(1000);
            synchronized (out) {
                synchronized (err) {
                    return new Result(code[0], out.toString().trim(), err.toString().trim());
                }
            }
        } catch (Exception e) {
            return new Result(-1, "", e.getClass().getSimpleName() + ": " + e.getMessage());
        } finally {
            if (process != null) {
                process.destroy();
            }
        }
    }

    static boolean isRootAvailable(StringBuilder detail) {
        Result r = run(60000, "id");
        boolean ok = r.out.contains("uid=0");
        if (detail != null) {
            detail.append(ok ? r.out : ("code " + r.code + " " + r.err));
        }
        return ok;
    }

    private static Thread drain(final InputStream in, final StringBuilder sink) {
        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    BufferedReader reader = new BufferedReader(new InputStreamReader(in));
                    String line;
                    while ((line = reader.readLine()) != null) {
                        synchronized (sink) {
                            sink.append(line).append('\n');
                        }
                    }
                } catch (IOException ignored) {
                    // stream closed
                }
            }
        });
        t.setDaemon(true);
        t.start();
        return t;
    }
}
