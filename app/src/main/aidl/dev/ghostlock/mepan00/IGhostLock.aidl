// The privileged half of the app, run in a process Shizuku spawns as the shell
// user. It has to live behind AIDL because the app itself cannot:
//   - read /sys/kernel/tracing/... (readtracefs is a shell-only group), and
//   - write /data/local/tmp (shell_data_file).
// Everything the exploit needs happens in here.
package dev.ghostlock.mepan00;

interface IGhostLock {

    /** Reserved by the Shizuku server. */
    void destroy() = 16777114;

    void exit() = 1;

    /** Write bytes to a path (used to stage the exploit library). */
    boolean pushFile(String path, byte[] data) = 2;

    /** Run a short command and return its combined output. */
    String runShell(String script, int timeoutSec) = 3;

    /**
     * Start the exploit detached and return immediately.
     * The host process never exits, so the caller must not block on it -- it
     * polls readText() on the fsync'd diagnostic instead.
     */
    boolean startFire(String soPath, String diagPath, String outPath, String[] env) = 4;

    /** Read a text file (the diagnostic), or null if it is not there yet. */
    String readText(String path) = 5;

    /** True if the given path exists. */
    boolean exists(String path) = 6;
}
