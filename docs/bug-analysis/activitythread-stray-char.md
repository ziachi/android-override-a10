# ActivityThread.java Stray Character

## Root Cause
Stray `n` character at beginning of comment line 6462 in ActivityThread.java.
Caused `javac` error: `';' expected` during `frameworks/base` compilation.
The stray char was introduced when manually integrating the PropsHooks hook.

## Investigation
```
frameworks/base/core/java/android/app/ActivityThread.java:6462: error: ';' expected
n                // Android Override: hook into app startup
^
```
Line started with `n` followed by `//` comment — javac interprets `n` as a variable reference without semicolon.

## Solution
```bash
sed -i '6462s/^n//' frameworks/base/core/java/android/app/ActivityThread.java
```
Remove the stray `n` character. Corrected patch provided in `patches/frameworks_base/core/ActivityThread.java.patch`.

## Lessons
- Always diff the patch before building — visual inspection catches typos
- Javac errors pointing to comment lines usually mean stray chars before the `//`
