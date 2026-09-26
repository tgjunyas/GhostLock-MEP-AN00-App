package dev.ghostlock.mepan00;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.Button;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.List;
import java.util.concurrent.TimeUnit;

import rikka.shizuku.Shizuku;

/**
 * GhostLock for Honor MEP-AN00 -- as little UI as the job needs.
 *
 *   选择 boot.img   read the kernel release out of a boot image and say whether the
 *                   bundled exploit was built for it. This is a gate, not a build
 *                   step: the offsets live inside preload.so at compile time, so a
 *                   mismatch means "this APK cannot help you" -- worth knowing
 *                   before spending the boot's single shot.
 *   激活            stage the library as shell, fire the chain, then take root
 *                   over the loopback daemon and load KernelSU.
 *
 * Requires Shizuku, because the KASLR leak reads tracefs (shell-only).
 */
public class MainActivity extends Activity {

    private static final int REQ_PICK_BOOT = 1001;
    private static final String KSU_PKG = "me.weishu.kernelsu";

    private final Handler ui = new Handler(Looper.getMainLooper());
    private TextView status, log;
    private Button pick, activate;
    private StringBuilder logBuf = new StringBuilder();

    private final Shizuku.OnRequestPermissionResultListener permListener =
            (requestCode, grantResult) -> {
                if (requestCode == Shell.REQ_SHIZUKU) {
                    if (grantResult == PackageManager.PERMISSION_GRANTED) {
                        say("✅ Shizuku 已授权");
                    } else {
                        say("❌ Shizuku 授权被拒");
                    }
                    refreshStatus();
                }
            };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        status = findViewById(R.id.status);
        log = findViewById(R.id.log);
        pick = findViewById(R.id.pick);
        activate = findViewById(R.id.activate);

        try {
            Shizuku.addRequestPermissionResultListener(permListener);
        } catch (Throwable ignored) {
            // Shizuku not installed: the status line will say so.
        }

        pick.setOnClickListener(v -> {
            Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
            i.addCategory(Intent.CATEGORY_OPENABLE);
            i.setType("*/*");
            startActivityForResult(i, REQ_PICK_BOOT);
        });

        activate.setOnClickListener(v -> {
            activate.setEnabled(false);
            new Thread(this::runActivation, "activate").start();
        });

        refreshStatus();
    }

    @Override
    protected void onDestroy() {
        try {
            Shizuku.removeRequestPermissionResultListener(permListener);
        } catch (Throwable ignored) {
        }
        super.onDestroy();
    }

    private void refreshStatus() {
        String running = Exploit.runningKernel();
        StringBuilder sb = new StringBuilder();
        sb.append("设备内核: ").append(running == null ? "?" : running).append('\n');
        sb.append("支持内核: ").append(BootImage.EXPECTED_KERNEL).append('\n');
        sb.append("uptime: ").append(Exploit.uptimeSeconds()).append("s\n");
        String why = Shell.unavailableReason();
        sb.append("Shizuku: ").append(why == null ? "就绪 ✅" : why + " ⚠");
        status.setText(sb.toString());
    }

    // ---------------------------------------------------------------- boot image

    @Override
    protected void onActivityResult(int req, int res, Intent data) {
        super.onActivityResult(req, res, data);
        if (req != REQ_PICK_BOOT || res != RESULT_OK || data == null) return;
        Uri uri = data.getData();
        if (uri == null) return;
        new Thread(() -> checkBootImage(uri), "bootimg").start();
    }

    private void checkBootImage(Uri uri) {
        say("—— 解析 boot.img ——");
        String release;
        try (InputStream in = getContentResolver().openInputStream(uri)) {
            if (in == null) {
                say("打不开这个文件");
                return;
            }
            release = BootImage.kernelRelease(in);
        } catch (IOException e) {
            say("读取失败: " + e.getMessage());
            return;
        }
        if (release == null) {
            say("这个文件里没找到内核版本串 —— 可能不是 boot 镜像，");
            say("或者内核是压缩的（本 App 不解压）。");
            return;
        }
        say("镜像里的内核: " + release);
        if (release.equals(BootImage.EXPECTED_KERNEL)) {
            say("✅ 与内置 exploit 的目标内核一致，可以激活。");
        } else {
            say("❌ 不匹配。内置 exploit 只支持:");
            say("   " + BootImage.EXPECTED_KERNEL);
            say("   这份固件需要为它重新构建 exploit（见 README）。");
        }
        String running = Exploit.runningKernel();
        if (running != null && !running.equals(release)) {
            say("⚠ 注意：这份 boot.img 和当前运行的内核不是同一个（当前 " + running + "）。");
        }
    }

    // ---------------------------------------------------------------- activation

    private void runActivation() {
        logBuf = new StringBuilder();
        say("—— GhostLock MEP-AN00 ——");

        if (!Shell.binderAlive()) {
            say("❌ Shizuku 没在运行。");
            say("   先安装并启动 Shizuku（首次启动需要 adb 或无线调试）。");
            done();
            return;
        }
        if (!Shell.hasPermission()) {
            say("请求 Shizuku 授权 ...");
            ui.post(Shell::requestPermission);
            say("   请在弹出的对话框里点允许，然后重新点“激活”。");
            done();
            return;
        }

        String running = Exploit.runningKernel();
        say("运行内核: " + running);
        if (running == null || !running.equals(BootImage.EXPECTED_KERNEL)) {
            say("❌ 当前内核不是内置 exploit 支持的那个，拒绝开火。");
            say("   （硬开只会白费这个 boot，甚至 panic）");
            done();
            return;
        }

        say("连接 Shizuku shell 服务 ...");
        if (!Shell.connect(this, 20000)) {
            say("❌ 连接失败: " + (Shell.lastError() == null ? "未知" : Shell.lastError()));
            say("   确认 Shizuku 正在运行并已授权本 App。");
            done();
            return;
        }
        say("✅ shell 服务已连接");
        String id = Shell.runShell("id", 15);
        if (id != null) say("   " + id.trim());

        if (Exploit.alreadyFired()) {
            say("❌ 本 boot 已经开过火了（一 boot 一发）。请重启设备后再试。");
            done();
            return;
        }

        say("以 shell 身份释放库到 " + Exploit.REMOTE_SO + " ...");
        if (!Exploit.stage(this)) {
            say("❌ 释放失败");
            done();
            return;
        }
        String up = Exploit.uptimeSeconds();
        say("uptime: " + up + "s" + (isSmall(up, 90) ? "  ⚠ 建议 ≥90s，可能不中" : ""));
        say("开火中（一 boot 一发，请勿重复）...");

        if (!Exploit.fire()) {
            say("❌ 启动失败（shell 侧拒绝）");
            done();
            return;
        }
        String diag = Exploit.awaitDiag(180);
        if (diag == null) {
            say("❌ 没拿到 diag");
            done();
            return;
        }
        Exploit.Verdict v = Exploit.verdict(diag);
        for (String line : Exploit.highlights(diag)) say("  " + line);

        if (!v.finished) {
            say("❌ 没跑完（diag " + v.bytes + " B）。");
            say("   小于 ~300 B 通常意味着根本没执行，不是普通的 miss。");
            done();
            return;
        }
        if (!v.root) {
            say("❌ 链跑完了但没拿到 root。重启后重试。");
            done();
            return;
        }
        say("✅ 拿到 root" + (v.restored ? "（misc_fops 已还原）" : ""));

        takeRootAndLoadKernelSu();
        done();
    }

    /**
     * The io daemon can hand out root. We take it for this process, which is
     * enough to exec KernelSU's ksud -- an app could not exec another app's
     * library, but a kernel-domain root process can.
     */
    private void takeRootAndLoadKernelSu() {
        if (!RootChannel.ping()) {
            say("⚠ io daemon 不可达（127.0.0.1:39555），跳过 KernelSU。");
            return;
        }
        say("通过 io daemon 给本进程授权 root ...");
        if (!RootChannel.grantRootToPid(android.os.Process.myPid())) {
            say("❌ 授权失败");
            return;
        }
        say("✅ 本进程现在是 uid 0 / kernel 域");

        String ks = ksuLibPath();
        if (ks == null) {
            say("⚠ 没装 KernelSU 管理器（" + KSU_PKG + "），跳过模块加载。");
            return;
        }
        say("KernelSU: " + ks);
        say("late-load 中 ...");
        String out = sh(ks + " late-load --allow-shell --package-name " + KSU_PKG);
        if (out != null && out.trim().length() > 0) {
            for (String l : out.trim().split("\n")) say("  " + l);
        }
        String id = sh("id");
        if (id != null && id.contains("uid=0")) say("✅ root 可用: " + id.trim());
        String dom = sh("cat /proc/self/attr/current");
        if (dom != null) say("   SELinux 域: " + dom.trim());
        String mods = sh("grep -i kernelsu /proc/modules");
        if (mods != null && mods.contains("kernelsu")) {
            say("✅ 模块已驻留: " + mods.trim());
        } else {
            say("   /proc/modules 里看不到 kernelsu 是正常的（KernelSU 会自我隐藏）；");
            say("   SELinux 域变成 u:r:ksu:s0 就说明它活着。");
        }
    }

    /** libksud.so ships the module built for the matching kernel. */
    private String ksuLibPath() {
        try {
            ApplicationInfo ai = getPackageManager().getApplicationInfo(KSU_PKG, 0);
            File f = new File(ai.nativeLibraryDir, "libksud.so");
            return f.isFile() ? f.getAbsolutePath() : null;
        } catch (PackageManager.NameNotFoundException e) {
            return null;
        }
    }

    // -------------------------------------------------------------------- plumbing

    private String sh(String cmd) {
        try {
            Process p = new ProcessBuilder("/system/bin/sh", "-c", cmd)
                    .redirectErrorStream(true).start();
            StringBuilder sb = new StringBuilder();
            try (BufferedReader r = new BufferedReader(
                    new InputStreamReader(p.getInputStream()))) {
                String l;
                while ((l = r.readLine()) != null) sb.append(l).append('\n');
            }
            p.waitFor(15, TimeUnit.SECONDS);
            return sb.toString();
        } catch (IOException | InterruptedException e) {
            return null;
        }
    }

    private static boolean isSmall(String up, int limit) {
        try {
            return Integer.parseInt(up.trim()) < limit;
        } catch (Exception e) {
            return false;
        }
    }

    private void say(String s) {
        logBuf.append(s).append('\n');
        final String text = logBuf.toString();
        ui.post(() -> {
            log.setText(text);
            View parent = (View) log.getParent();
            if (parent instanceof ScrollView) ((ScrollView) parent).fullScroll(View.FOCUS_DOWN);
        });
    }

    private void done() {
        ui.post(() -> {
            activate.setEnabled(true);
            refreshStatus();
        });
    }
}
