# spu_iso_tool

Decrypt and encrypt `lv0ldr` / `metldr` style PS3 SPU isolation containers — a small, dependency-free C tool.

It implements a custom AES-128 **CCM-style** scheme (AES-CTR for the body plus a CBC-MAC
authentication tag), matching the layout used by these containers.

It ships as both a **command-line tool** (`spu_iso_tool`) and a **Qt GUI** (`spu_iso_gui`).

## GUI

The Qt GUI exposes a panel for **metldr** and a panel for **lv0ldr**, each with its own
input/output files and keys. Enable one or both — when both are enabled they are processed in a
single run. Pick **Decrypt** (needs only the master key) or **Encrypt** (also shows the IV, nonce
and ekey fields) at the top; results and any errors are shown in the log at the bottom.

Prebuilt GUI packages are attached to each [release](https://github.com/zecoxao/spu_iso_tool/releases):

| Platform | Asset                              |
|----------|------------------------------------|
| Windows  | `spu_iso_gui-windows-x64.zip`      |
| macOS    | `spu_iso_gui-macos-universal.zip`  |
| Linux    | `spu_iso_gui-linux-x86_64.AppImage`|

## Command-line usage

```
Encrypt: spu_iso_tool enc --key <hex> --iv <hex> --nonce <hex> --ekey <hex> <infile> <outfile>
Decrypt: spu_iso_tool dec --key <hex> <infile> <outfile>
```

### Arguments

| Flag       | Bytes | Used in     | Description                                    |
|------------|-------|-------------|------------------------------------------------|
| `--key`    | 16    | enc + dec   | AES-128 master key                             |
| `--iv`     | 12    | enc         | CTR / CBC-MAC IV (nonce)                       |
| `--nonce`  | 12    | enc         | Console nonce stored in the header             |
| `--ekey`   | 16    | enc         | Scramble / encrypted key stored in the header  |

On decryption the IV, nonce and ekey are read back from the container header, so only the
master key is required. Decryption verifies the CBC-MAC tag and **fails closed** (non-zero
exit, no output written) if the tag does not match.

### Examples

```sh
# Encrypt
spu_iso_tool enc \
  --key 000102030405060708090a0b0c0d0e0f \
  --iv 0a0a0a0a0a0a0a0a0a0a0a0a \
  --nonce 0b0b0b0b0b0b0b0b0b0b0b0b \
  --ekey ffeeddccbbaa99887766554433221100 \
  plain.bin container.bin

# Decrypt (verifies the MAC)
spu_iso_tool dec --key 000102030405060708090a0b0c0d0e0f container.bin plain.bin
```

## Container layout

```
offset  size  field
0x00    4     body block count N (big-endian)
0x04    12    CTR IV / CBC-MAC nonce
0x10    4     body block count N (mirror, big-endian)
0x14    12    console nonce
0x20    16    scramble / encrypted key
0x30    16    CBC-MAC authentication tag
0x40    ...   AES-CTR encrypted body (N * 16 bytes)
```

## Building

### CMake (Windows, macOS, Linux)

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

The CLI binary is produced as `build/spu_iso_tool` (`build/Release/spu_iso_tool.exe` on Windows).

The **Qt GUI** is built automatically when Qt 6 (Widgets) is found. Control it explicitly with
`-DSPU_BUILD_GUI=ON` (require Qt), `-DSPU_BUILD_GUI=OFF` (CLI only), or the default `AUTO`:

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Release -DSPU_BUILD_GUI=ON -DCMAKE_PREFIX_PATH=/path/to/Qt/6.x/<kit>
cmake --build build --config Release
```

### Visual Studio

Open `spu_iso_tool.sln` and build the **Release | x64** configuration (CLI only).

## Downloads

Prebuilt binaries for Windows, macOS and Linux are attached to each
[release](https://github.com/zecoxao/spu_iso_tool/releases): the `spu_iso_tool-*` CLI binaries and
the `spu_iso_gui-*` GUI packages.

## Credits

Proudly created by ZeroTolerance, ported by Zecoxao.

## License

GPL-2.0-or-later. The bundled AES implementation (`aes.c` / `aes.h`) is from
[PolarSSL](https://tls.mbed.org/) (Brainspark B.V.), licensed under the GNU GPL v2 or later.
See [LICENSE](LICENSE).
