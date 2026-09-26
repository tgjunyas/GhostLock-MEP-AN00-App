package dev.ghostlock.mepan00;

import android.content.ComponentName;
import android.content.Context;
import android.content.ServiceConnection;
import android.content.pm.PackageManager;
import android.os.IBinder;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import rikka.shizuku.Shizuku;

/**
 * The app-side half of the Shizuku user service.
 *
 * Why a user service instead of Shizuku's process API: the exploit's first stage
 * is a KASLR leak that reads /sys/kernel/tracing/per_cpu/cpuN/trace_pipe_raw, and
 * that path is `-r--r----- root readtracefs`. An untrusted_app is neither root nor
 * in the readtracefs group, so it cannot read it; the shell user (uid 2000) can.
 * Shizuku is how an app borrows the shell identity, and the sanctioned way to use
 * it is to bind a service of your own that then runs in a shell process.
 *
 * Everything privileged therefore happens in GhostLockService, on the far side of
 * this bridge.
 */
public final class Shell {

    public static final int REQ_SHIZUKU = 4001;

    private static IGhostLock svc;
    private static CountDownLatch latch;
    private static boolean binding;
    private static String lastError;

    private Shell() {}

    // ------------------------------------------------------------------ shizuku

    public static boolean binderAlive() {
        try {
            return Shizuku.pingBinder();
        } catch (Throwable t) {
            return false;
        }
    }

    public static boolean hasPermission() {
        try {
            return !Shizuku.isPreV11()
                    && Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED;
        } catch (Throwable t) {
            return false;
        }
    }

    public static void requestPermission() {
        Shizuku.requestPermission(REQ_SHIZUKU);
    }

    /** Human-readable reason the bridge is unusable, or null when it is ready. */
    public static String unavailableReason() {
        if (!binderAlive()) return "Shizuku 没在运行（先启动 Shizuku 应用）";
        if (!hasPermission()) return "还没给本 App 授权（点“激活”会弹授权框）";
        if (svc == null) return "shell 服务未连接（点“激活”会自动连接）";
        return null;
    }

    // ------------------------------------------------------------------- binding

    private static final ServiceConnection CONN = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder binder) {
            svc = IGhostLock.Stub.asInterface(binder);
            if (latch != null) latch.countDown();
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            svc = null;
        }
    };

    private static Shizuku.UserServiceArgs args(Context ctx) {
        return new Shizuku.UserServiceArgs(
                new ComponentName(ctx.getPackageName(), GhostLockService.class.getName()))
                .daemon(false)
                .processNameSuffix("shell")
                .debuggable(false)
                .version(1);
    }

    /**
     * Bind the shell service and wait for it. Safe to call repeatedly; returns
     * true once the far side is usable.
     */
    public static boolean connect(Context ctx, long timeoutMs) {
        if (svc != null) return true;
        if (binding) return await(timeoutMs);
        binding = true;
        lastError = null;
        latch = new CountDownLatch(1);
        try {
            Shizuku.bindUserService(args(ctx), CONN);
        } catch (Throwable t) {
            lastError = t.toString();
            binding = false;
            return false;
        }
        boolean ok = await(timeoutMs);
        binding = false;
        return ok;
    }

    private static boolean await(long timeoutMs) {
        try {
            if (latch != null && !latch.await(timeoutMs, TimeUnit.MILLISECONDS)) {
                lastError = "连接 shell 服务超时";
                return false;
            }
        } catch (InterruptedException e) {
            return false;
        }
        return svc != null;
    }

    public static String lastError() {
        return lastError;
    }

    // ------------------------------------------------------------------ calls

    public static boolean pushFile(String path, byte[] data) {
        try {
            return svc != null && svc.pushFile(path, data);
        } catch (Throwable t) {
            return false;
        }
    }

    public static String runShell(String script, int timeoutSec) {
        try {
            return svc == null ? null : svc.runShell(script, timeoutSec);
        } catch (Throwable t) {
            return null;
        }
    }

    public static boolean startFire(String so, String diag, String out, String[] env) {
        try {
            return svc != null && svc.startFire(so, diag, out, env);
        } catch (Throwable t) {
            return false;
        }
    }

    public static String readText(String path) {
        try {
            return svc == null ? null : svc.readText(path);
        } catch (Throwable t) {
            return null;
        }
    }

    public static boolean exists(String path) {
        try {
            return svc != null && svc.exists(path);
        } catch (Throwable t) {
            return false;
        }
    }
}
