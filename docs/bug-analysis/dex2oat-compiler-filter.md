# dex2oat Duplicate Compiler Filter (CRITICAL)

## Root Cause
`PRODUCT_SYSTEM_SERVER_COMPILER_FILTER` was set in BOTH:
- `device/xiaomi/santoni/device.mk` -> `speed-profile`
- `vendor/qassa/config/common.mk` -> `speed`

Android product inheritance **CONCATENATES** product variables (does NOT override).
Result: `"speed-profile speed"` passed to dex2oat as `--compiler-filter=speed-profile speed`.
dex2oat interprets bare `speed` as unknown argument and crashes.

## Investigation
```bash
# Check dexpreopt config (source of truth for dex2oat args)
cat out/target/product/santoni/dexpreopt.config | python -m json.tool | grep -i filter
# Shows: "SystemServerCompilerFilter": "speed-profile speed"

# Verify in build.ninja
grep "compiler-filter" out/soong/build.ninja | head -5
# Shows: --compiler-filter=speed-profile speed
```

**Important:** `grep 'compiler-filter' build.ninja | head -1` was MISLEADING — first match was from boot image dexpreopt (correct), not from app-specific lines (broken).

## Solution
Remove from `device/xiaomi/santoni/device.mk`:
```makefile
# REMOVED — set only in vendor/qassa/config/common.mk
# PRODUCT_DEX_PREOPT_DEFAULT_COMPILER_FILTER := speed-profile
# PRODUCT_SYSTEM_SERVER_COMPILER_FILTER := speed-profile
```

Only set in ONE place: `vendor/qassa/config/common.mk`.

After removing, must nuke soong cache:
```bash
rm -rf out/soong/.bootstrap out/soong/build.ninja out/soong/build.ninja.d
```

## Lessons
- Android product inheritance CONCATENATES — never set same var in device.mk + vendor config
- `dexpreopt.config` JSON is source of truth, not build.ninja grep
- Soong caches dex2oat commands — must fully nuke `.bootstrap` + `build.ninja` + `.d`
- Always check BOTH device.mk and vendor config for duplicate product vars
