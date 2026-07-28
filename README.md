# valonsodev Morphe Patches

Morphe patches for Android TV applications.

## Patches

<!-- PATCHES_START EXPANDED -->

The release workflow generates this section from `patches-list.json`.

<!-- PATCHES_END -->

## Use with Morphe

Add this repository as a patch source:

```text
https://github.com/valonsodev/morphe-patches
```

Or use the Morphe source link:

```text
https://morphe.software/add-source?github=valonsodev/morphe-patches
```

The Prime Video `Remove ads` patch currently supports:

```text
com.amazon.amazonvideo.livingroom
6.24.2+v15.5.0.300-allAbis
6.24.4+v16.0.0.103-allAbis
APKM
```

The optional `Clone Prime Video` patch installs the patched application under
the `.mod` package suffix so it can coexist with a non-removable system copy.
The clone has separate application data and therefore requires its own login.

## Credits

The `Clone Prime Video` patch is adapted from
[ajstrick81/morphe-androidtv-patches](https://github.com/ajstrick81/morphe-androidtv-patches).
Thanks to ajstrick81 and the repository contributors for the original
package, provider-authority, and custom-permission rewrite.

## Build

Build the consumable patch bundle:

```bash
./gradlew :patches:buildAndroid
```

Output:

```text
patches/build/libs/patches-<version>.mpp
```

## License

valonsodev Morphe Patches are licensed under the
[GNU General Public License v3.0](LICENSE).
