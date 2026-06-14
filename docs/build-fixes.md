# Build Fixes & Pitfalls (keepQASSA Android 10)

## Fix #1 — ActivityThread.java stray character
**Problem:** Javac error `';' expected` at line 6462 of ActivityThread.java.
**Root cause:** Stray `n` character at beginning of comment line when integrating PropsHooks.
**Fix:** Remove stray char. Corrected patch included in `patches/frameworks_base/core/ActivityThread.java.patch`.

## Fix #2 — Webview LFS pointers not pulled
**Problem:** `external/chromium-webview/prebuilt/{arm,arm64}/webview.apk` were 133-134 byte Git LFS pointers instead of actual APKs.
**Root cause:** `repo sync --depth=1` does not pull LFS objects.
**Fix:** Run `git lfs install && git lfs pull` in each prebuilt directory:
```bash
cd external/chromium-webview/prebuilt/arm && git lfs install && git lfs pull
cd external/chromium-webview/prebuilt/arm64 && git lfs install && git lfs pull
```

## Fix #3 — dex2oat duplicate compiler filter (CRITICAL)
**Problem:** `dex2oat: Unknown argument: speed` — bare `speed` after `--compiler-filter=speed`.
**Root cause:** `PRODUCT_SYSTEM_SERVER_COMPILER_FILTER` set in BOTH `device/xiaomi/santoni/device.mk` AND `vendor/qassa/config/common.mk`. Android product inheritance **CONCATENATES** (not overrides) product variables → `"speed speed"` in `dexpreopt.config`.
**Fix:** Remove `PRODUCT_SYSTEM_SERVER_COMPILER_FILTER` and `PRODUCT_DEX_PREOPT_DEFAULT_COMPILER_FILTER` from `device.mk`. Only set in ONE place (`vendor/qassa/config/common.mk`).

### Key lesson
> Android product inheritance CONCATENATES product variables — setting the same variable in device.mk + vendor common.mk produces duplicate values, NOT an override. Always check `out/target/product/<device>/dexpreopt.config` to verify.

## Fix #4 — Soong bootstrap cache stale
**Problem:** After fixing device.mk, soong `build.ninja` still had old `--compiler-filter=speed speed` baked in.
**Fix:** Nuke soong cache:
```bash
rm -rf out/soong/.bootstrap out/soong/build.ninja out/soong/build.ninja.d
```
