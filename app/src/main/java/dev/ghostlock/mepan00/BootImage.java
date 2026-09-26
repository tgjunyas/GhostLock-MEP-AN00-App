package dev.ghostlock.mepan00;

import java.io.IOException;
import java.io.InputStream;

/**
 * Pulls the kernel release string out of an Android boot image.
 *
 * That string ("6.6.118-android15-8-gf17133276a57-abogki518694926-4k") is the
 * fingerprint the bundled exploit was built for: every offset in target.h is a
 * property of that exact kernel build. So picking a boot.img lets us answer
 * "would this exploit work on the firmware this image belongs to?" *before*
 * spending the boot's single shot.
 *
 * The kernel inside a MEP-AN00 boot image is NOT compressed -- it is a raw arm64
 * Image starting with the EFI stub's "MZ" -- so this is a header parse plus a
 * substring search, no decompressor needed. (If a future image turns out to be
 * compressed this returns null rather than a wrong answer.)
 */
public final class BootImage {

    /** The kernel release the bundled preload.so was built for. */
    public static final String EXPECTED_KERNEL =
            "6.6.118-android15-8-gf17133276a57-abogki518694926-4k";

    private static final int ANDROID_MAGIC = 0x414e44524f494421; // "ANDROID!"
    private static final int PAGE = 4096;
    private static final byte[] NEEDLE = "Linux version ".getBytes();

    private BootImage() {}

    /**
     * @return the kernel release (uname -r) found in the image, or null if the
     *         file is not a boot image / no kernel version string was found.
     */
    public static String kernelRelease(InputStream in) throws IOException {
        byte[] head = new byte[PAGE];
        int n = readFully(in, head);
        if (n < 64) return null;

        long magic = 0;
        for (int i = 0; i < 8; i++) magic = (magic << 8) | (head[i] & 0xffL);
        if (magic != ANDROID_MAGIC) return null;

        int kernelSize = le32(head, 8);
        int pageSize = le32(head, 36);
        if (pageSize <= 0 || pageSize > (1 << 20)) pageSize = PAGE;

        // The header occupies the first page (v3/v4) or pageSize bytes (v0-v2);
        // the kernel payload follows immediately.
        int skip = pageSize;
        if (kernelSize <= 0) {
            kernelSize = Integer.MAX_VALUE; // unknown: scan to EOF
        }
        // Skip whatever of the header we have not consumed yet.
        for (int left = skip - n; left > 0; ) {
            long dropped = in.skip(left);
            if (dropped <= 0) break;
            left -= (int) dropped;
        }
        return findRelease(in, kernelSize);
    }

    /** Sliding-window search for "Linux version <release>" over a byte stream. */
    private static String findRelease(InputStream in, int limit) throws IOException {
        byte[] buf = new byte[64 * 1024];
        byte[] carry = new byte[NEEDLE.length - 1];
        int carryLen = 0;
        long consumed = 0;

        while (consumed < limit) {
            int want = (int) Math.min(buf.length, limit - consumed);
            int got = in.read(buf, 0, want);
            if (got <= 0) break;
            consumed += got;

            // Work on carry + this chunk so a needle straddling a boundary is seen.
            byte[] win = new byte[carryLen + got];
            System.arraycopy(carry, 0, win, 0, carryLen);
            System.arraycopy(buf, 0, win, carryLen, got);

            for (int i = 0; i + NEEDLE.length <= win.length; i++) {
                if (matches(win, i)) {
                    String rel = readRelease(win, i + NEEDLE.length);
                    if (rel != null) return rel;
                }
            }
            carryLen = Math.min(carry.length, win.length);
            System.arraycopy(win, win.length - carryLen, carry, 0, carryLen);
        }
        return null;
    }

    private static boolean matches(byte[] w, int at) {
        for (int i = 0; i < NEEDLE.length; i++) {
            if (w[at + i] != NEEDLE[i]) return false;
        }
        return true;
    }

    /** The release string runs from just after the needle to the first space. */
    private static String readRelease(byte[] w, int from) {
        StringBuilder sb = new StringBuilder(64);
        for (int i = from; i < w.length && sb.length() < 128; i++) {
            char c = (char) (w[i] & 0xff);
            if (c == ' ' || c == 0 || c == '\n') break;
            if (c < 0x20 || c > 0x7e) return null;
            sb.append(c);
        }
        String s = sb.toString();
        return s.startsWith("6.") || s.startsWith("5.") ? s : null;
    }

    private static int le32(byte[] b, int off) {
        return (b[off] & 0xff) | ((b[off + 1] & 0xff) << 8)
                | ((b[off + 2] & 0xff) << 16) | ((b[off + 3] & 0xff) << 24);
    }

    private static int readFully(InputStream in, byte[] buf) throws IOException {
        int off = 0;
        while (off < buf.length) {
            int r = in.read(buf, off, buf.length - off);
            if (r < 0) break;
            off += r;
        }
        return off;
    }
}
