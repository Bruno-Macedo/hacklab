xfreerdp /f /u:htb-student /p:'Academy_WinFun!' /v:$TARGET /dynamic-resolution 
  /f: fullscreen
  /dynamic-resolution 
  +clipboard
  /drive:linux,/home/plaintext/htb/academy/filetransfer = mount
  /workarea
  /pth:NTLM_HASH
  /cert:ignore
  +drives 
  /pth:NTLM_HASH

  S-1-5-21-2614195641-1726409526-3792725429-1003


   1   exploit/windows/local/cve_2020_1048_printerdemon               Yes                      The target appears to be vulnerable.
 2   exploit/windows/local/cve_2020_1337_printerdemon               Yes                      The target appears to be vulnerable.
 3   exploit/windows/local/ms16_032_secondary_logon_handle_privesc  Yes                      The service is running, but could not be validated.
 4   exploit/windows/local/ms16_075_reflection                      Yes                      The target appears to be vulnerable