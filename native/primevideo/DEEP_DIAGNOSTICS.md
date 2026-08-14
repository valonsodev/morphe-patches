# Prime Video deep preroll diagnostics

Build identifier: `primehook-20260813.01-deep-diagnostics`

This diagnostic build combines the existing PRS/Regolith filters with a
length-preserving QuickJS player-source patch and persistent, uncapped evidence
capture. It is intended for controlled playback testing, not as a quiet release
build.

## Persistent files

The hook derives the package name from `/proc/self/cmdline` and appends to:

```text
/data/user/0/<package>/files/pvhook-diagnostics.log
/data/user/0/<package>/files/pvhook-candidate-buffers.bin
```

The first file contains structured text events. The second contains complete
pre-mutation candidate buffers framed by `PVHOOK_RAW_BEGIN` and
`PVHOOK_RAW_END`. It can contain Regolith responses, PRS JSON and the complete
player source, including URLs and session identifiers. Treat it as private.

No rotation or size ceiling is applied. Remove the files between controlled
runs when a clean capture is needed.

Pull from the development clone without relying on external-storage access:

```bash
adb exec-out run-as com.amazon.amazonvideo.livingroom.dev \
  cat files/pvhook-diagnostics.log > pvhook-diagnostics.log

adb exec-out run-as com.amazon.amazonvideo.livingroom.dev \
  cat files/pvhook-candidate-buffers.bin > pvhook-candidate-buffers.bin
```

Clear before a new run:

```bash
adb shell run-as com.amazon.amazonvideo.livingroom.dev \
  sh -c 'truncate -s 0 files/pvhook-diagnostics.log; truncate -s 0 files/pvhook-candidate-buffers.bin'
```

If `truncate` is unavailable, stop the app and use `rm` on the two explicit
filenames. The hook recreates them at the next process start.

## Important events

- `JNI_OnLoad`: immutable build ID, persistent file descriptors and hook setup.
- `COPY_CANDIDATE`: copy kind, caller offset, source/destination pointers,
  lengths, marker mask, offsets and pre-mutation hash.
- `COPY_SAMPLE`: early and periodic samples for otherwise uninteresting copies.
- `REGOLITH_RESULT`: exact outcome, write count, items and post-mutation hash.
- `PRS_MATCH` / `PRS_SKIP`: PRS structure and parser results.
- `PLAYER_BUNDLE`: online and EXPL source-patch capability and result.
- `RUST_PROBE_MATCH` / `RUST_PROBE_DONE`: telemetry-only discovery of the
  anonymously mapped Rust player using the IDA-verified ContentType parser
  signature. The diagnostic build does not patch Rust code.

Marker mask:

```text
0x001 adDeliverySessionId
0x002 intraTitlePlaylist
0x004 measurement
0x008 playlist key
0x010 exact minified "playlist":[ spelling
0x020 syntactically valid playlist array opener
0x040 matching playlist array closer
0x080 online reportAssetFulfilment definition
0x100 EXPL createPrerollPeriods definition
0x200 Adbreak0_Ad period-name marker
```

## Source-patch behavior

The online patch locates the shared `reportAssetFulfilment` function
semantically. It discovers the minifier-selected local assigned from
`response.playlist`, then changes the later loop comparison into an assignment
that empties the same array and evaluates false. Variable names may change and
the source length does not.

The EXPL/cache constructor is detected and patched independently using the same
local-variable analysis. Each capability reports `patched`, `not_present`,
`ambiguous`, `structure_changed` or `replacement_too_long`. Ambiguous or changed
structures are never modified.

## Rust limitation

IDA confirms that `ContentType` parsing at ELF offset `0x123BD90` is a good
classifier for `Advertisement`, `AdTransition` and `UnresolvedAdBreak`, but it
is downstream of media-period construction. The current Zig hook has no safe
ARM Thumb trampoline, executable-memory restoration or instruction-cache
flush. This build therefore finds and logs the runtime base without installing
an inline Rust detour. A rushed detour could crash the player or alter the
timing being investigated.

## Validation

```bash
zig build test
zig build
```

The host tests include renamed-variable source snippets, ambiguity/fail-closed
behavior, whitespace-tolerant Regolith JSON, malformed bracket rejection and
the complete captured production player bundle. Both Android ABIs are rebuilt
into the Morphe resources by `zig build`.
