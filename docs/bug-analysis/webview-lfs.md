# Webview LFS Pointers Not Pulled

## Root Cause
`external/chromium-webview/prebuilt/{arm,arm64}/webview.apk` were 133-134 byte Git LFS pointer files instead of actual APK binaries (~40MB each).
`repo sync --depth=1` does NOT pull Git LFS objects — it only fetches the pointer files.

## Investigation
```bash
$ file external/chromium-webview/prebuilt/arm/webview.apk
webview.apk: ASCII text  # Should be: Zip archive data (APK)

$ cat external/chromium-webview/prebuilt/arm/webview.apk
version https://git-lfs.github.com/spec/v1
oid sha256:abc123...
size 41234567
```
Build failed with invalid APK error during dexpreopt — cannot dex2oat a text file.

## Solution
```bash
cd external/chromium-webview/prebuilt/arm
git lfs install && git lfs pull

cd external/chromium-webview/prebuilt/arm64
git lfs install && git lfs pull
```
Each directory is a separate git repo — LFS must be pulled per-repo.

## Lessons
- `repo sync --depth=1` skips LFS objects — always run `git lfs pull` after
- Chromium-webview prebuilts are separate git repos, not part of main tree
- Check `file` command output on prebuilt APKs to verify they are actual binaries
