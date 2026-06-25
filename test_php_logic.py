import sys, json
sys.path.insert(0, '.')
from yang_web.core.php_logic import analyze_and_solve

test_src = """<?php
if(isset($_GET['syc'])&&preg_match('/^Welcome to GEEK 2023!$/i', $_GET['syc']) && $_GET['syc'] !== 'Welcome to GEEK 2023!') {
    if (intval($_GET['lover']) < 2023 && intval($_GET['lover'] + 1) > 2024) {
        if (isset($_POST['qw']) && $_POST['yxx']) {
            $array1 = (string)$_POST['qw']; $array2 = (string)$_POST['yxx'];
            if (sha1($array1) === sha1($array2)) {
                if (isset($_POST['SYC_GEEK.2023'])&&($_POST['SYC_GEEK.2023'] = "flag{test}")) {
                    echo "WIN";
                }
            }
        }
    }
}
?>"""

result = analyze_and_solve("http://test.com", test_src)
with open('php_logic_test.json', 'w', encoding='utf-8') as f:
    json.dump(result, f, indent=2, ensure_ascii=False)
print(json.dumps(result, indent=2, ensure_ascii=False))
