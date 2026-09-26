# GhostLock for Honor MEP-AN00 — App

A three-button Android app around the MEP-AN00 exploit for
CVE-2026-43499 (the exploit is shipped inside this repo as
`app/src/main/jniLibs/arm64-v8a/libgl.so`, so this repo builds on its own):
open it, tap **激活**, get root and KernelSU. Plus a **选择 boot.img** gate that
tells you whether the bundled exploit matches your firmware *before* you spend
the boot's single shot.

Root is lost on reboot. That is a property of the exploit, not the app.

## Requirements

| | |
|---|---|
| Device | Honor MEP-AN00 (HONOR 500 Pro, SM8750) |
| Kernel | `6.6.118-android15-8-gf17133276a57-abogki518694926-4k` — **exact match, gated** |
| Firmware | MEP-AN00 10.0.0.175(C00E170R404P2) |
| [Shizuku](https://shizuku.rikka.app/) | installed **and started** (needed — see below) |
| [KernelSU Manager](https://github.com/tiann/KernelSU) | v3.3.0+ installed (`me.weishu.kernelsu`) |

## Install

Grab the APK from the **Actions** tab (build artifact) or build it yourself:

```sh
./gradlew assembleRelease
# -> app/build/outputs/apk/release/app-release.apk
```

It is signed with the debug key, so `adb install` works directly.

## Usage

1. Start **Shizuku** (first launch needs adb or wireless debugging once).
2. Install and open the app. The header shows the running kernel, the supported
   kernel, and whether Shizuku is ready.
3. Optionally tap **选择 boot.img** and pick your firmware's boot image — the app
   reads the kernel release out of it and says whether it matches.
4. Reboot if you have not just done so, wait ~90 s, then tap **激活**.
5. Watch the log. Success looks like `rootchain: ... install_child_root=1` then
   `run: route returned ... root=1`, followed by KernelSU's late-load.

One shot per boot. If the chain finishes without root, reboot and try again —
tapping 激活 twice on the same boot has never worked and is refused.

## Why Shizuku is required

The exploit's first stage is a KASLR leak that reads
`/sys/kernel/tracing/per_cpu/cpuN/trace_pipe_raw`. On this kernel that path is:

```
-r--r----- 1 root readtracefs  .../per_cpu/cpu0/trace_pipe_raw
drwxr-x--- 8 root readtracefs  .../per_cpu
```

An app (`untrusted_app`) is neither root nor in the `readtracefs` group, so it
cannot read it and the leak fails before anything else runs. The **shell** user
(uid 2000) is in that group, which is why every adb-based run of this exploit
works. Shizuku is how an app borrows that identity.

So the app does all privileged work through Shizuku: it streams the library into
`/data/local/tmp` (an app cannot write `shell_data_file`), fires the chain there,
and reads the diagnostic back over the same channel.

The mechanism is Shizuku's **user service**: `IGhostLock.aidl` defines a tiny
interface, `GhostLockService` implements it, and `Shell.connect()` binds it. The
service runs in a process Shizuku spawns as shell, so everything it launches —
including the exploit — inherits that identity. (`Shizuku.newProcess` is private
in current API versions, so this is the supported route.)

## What the app does, step by step

1. Check `uname -r` against the kernel the bundled `libgl.so` was built for.
2. Refuse if this boot has already been fired.
3. Stream `libgl.so` from the APK into `/data/local/tmp/gl.so` as shell.
4. Fire: `LD_PRELOAD=/data/local/tmp/gl.so` into `/system/bin/sh`, detached, with
   the verified env (`SLIDE_DIAG`, `CFI_SKIP_VERIFY`, `NEO11_ROOT_CHAIN`,
   `SLIDE_CARRIER=sigreturn`, …), then poll the fsync'd diagnostic.
5. On `root=1`: connect to the exploit's io daemon on `127.0.0.1:39555` and ask it
   to grant root to this process (that daemon exists precisely so an app can do
   this — an app cannot reach the su socket under `/data/local/tmp`).
6. With root, run KernelSU's own `libksud.so late-load --allow-shell` — the
   library ships the module built for the matching kernel, so nothing needs
   recompiling or CRC forging.

## 选择 boot.img — what it is and is not

It is a **gate, not a build step**. Every offset in the exploit is a `#define`
compiled into `libgl.so`; the app cannot re-derive them at runtime. So picking a
boot image lets the app answer "was this APK built for that firmware?" — which is
worth knowing before burning the boot's one shot — but it cannot *adapt* the
exploit to a new firmware.

The image parser is small because the kernel inside a MEP-AN00 boot image is
**not compressed**: it is a raw arm64 `Image` starting with the EFI stub's `MZ`,
so the app parses the Android boot header, takes the kernel section, and scans it
for `Linux version <release>`.

### Supporting a different firmware

Rebuild the exploit against that kernel's offsets (see the exploit repo's
`docs/OFFSETS.md` — several constants, notably `STRUCT_SLAB_CACHE_OFF` and the
waiter shift, are **not** portable and must be re-derived), then drop the new
`preload.so` in as `app/src/main/jniLibs/arm64-v8a/libgl.so` and update
`EXPECTED_KERNEL` in `BootImage.java`.

## Limitations

- **One shot per boot.** The write primitive is a one-shot UAF.
- **Not a persistent root.** KernelSU is late-loaded; a reboot clears it.
- **Exact kernel only.** A different firmware build has different offsets.
- After KernelSU comes up, SELinux returns to `Enforcing` and the framework may
  need a moment. If apps look offline or a newly installed app has no launcher
  icon, restart the launcher — do not reboot:
  `kill -9 $(pidof com.hihonor.android.launcher)`.
- Device-owner use only.

## Credits

- Exploit: the MEP-AN00 GhostLock port for CVE-2026-43499 (bundled here as
  `libgl.so`; its source lives in a separate package, not in this repo)
- [Shizuku](https://github.com/RikkaApps/Shizuku) — shell identity
- [tiann/KernelSU](https://github.com/tiann/KernelSU) — LKM + `ksud` late-load
- [YuKongA/ghostlock-app](https://github.com/YuKongA/ghostlock-app) — the shape of
  a single-button GhostLock app

## License

[Apache-2.0](LICENSE).
