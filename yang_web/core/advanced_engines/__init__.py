# -*- coding: utf-8 -*-
"""Advanced encoding/cipher engines for Yang-Web.

Adds 20+ missing encoding/cipher types to fully match and exceed reference tools.
All engines are self-contained with zero external dependencies beyond Python stdlib.
"""

import re
import base64
import codecs
import struct
from typing import Optional, Tuple

# 重导出全部原子符号，保持 `from yang_web.core.advanced_engines import X` 契约不变
from ._esoteric import (OOK_MAP, brainfuck_encode, brainfuck_decode, ook_encode, ook_decode, jsfuck_encode, jsfuck_decode, aaencode_decode, aaencode_encode, jjencode_decode, jjencode_encode)
from ._base9192 import (_B91_ALPHABET, base91_encode, base91_decode, _B92_ALPHABET, base92_encode, base92_decode)
from ._mailbin import (quoted_printable_encode, quoted_printable_decode, uuencode, uudecode, XXENCODE_ALPHABET, xxencode, xxdecode)
from ._rot import (rot47_encode, rot47_decode, rot5_encode, rot5_decode, rot18_encode, rot18_decode, rot8000_encode, rot8000_decode)
from ._misc import (utf7_encode, utf7_decode, ZW_MAP, ZW_TO_BITS, zerowidth_encode, zerowidth_decode, punycode_encode, punycode_decode, shellcode_encode, shellcode_decode, _xor_bytes)
from ._registry import (ADVANCED_ENCODERS, list_advanced, get_advanced_encoder)
