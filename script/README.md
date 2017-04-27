# Tools Util
Contains the testing & release tools

## about the ERROR in test
cause the ssserver can not identify the different protocol based on tcp from each ss connection
the nc command can cause the server get error in handshake, that's should be correct
to make the script clean I set the log level into the Fatal

## About shadowsocks.exe
Copied `goagent.exe`, modified the string table and icon using reshack.
Thanks for the taskbar project created by @phuslu.
