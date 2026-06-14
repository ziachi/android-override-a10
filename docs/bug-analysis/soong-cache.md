# Soong Bootstrap Cache Stale

## Root Cause
After fixing `device.mk` (removing duplicate compiler filter), soong build.ninja still had old `--compiler-filter=speed-profile speed` baked in. The soong bootstrap cache was not invalidated by the device.mk change.

## Investigation
```bash
# Fixed device.mk but build still fails
grep "compiler-filter" out/soong/build.ninja | grep -v "^#"
# Still shows: --compiler-filter=speed-profile speed

# Touching build.ninja insufficient — soong regenerates from .bootstrap
```

## Solution
```bash
rm -rf out/soong/.bootstrap
rm -f out/soong/build.ninja
rm -f out/soong/build.ninja.d
```
This forces full soong rebuild (28275+ targets) — takes ~15-20 minutes on VPS.

**Note:** `nohup mka` requires `source build/envsetup.sh && lunch` in the same bash context — cannot be run standalone.

## Lessons
- Soong bootstrap caches are aggressive — device.mk changes do not always trigger regeneration
- Must delete ALL three: `.bootstrap/`, `build.ninja`, `build.ninja.d`
- `nohup mka` will not work without envsetup.sh sourced in same session
