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