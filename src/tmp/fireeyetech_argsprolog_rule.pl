processArguments('icacls . /grant Everyone:F /T /C /Q',wannacryattack).
processArguments('attrib +h +s <Drive_Letter>:\$RECYCLE',wannacryattack).
processArguments('taskkill.exe /f /im Microsoft.Exchange.\*',wannacryattack).
processArguments('taskkill.exe /f /im MSExchange\*',wannacryattack).
processArguments('taskkill.exe /f /im sqlserver.exe',wannacryattack).
processArguments('taskkill.exe /f /im sqlwriter.exe',wannacryattack).
processArguments('taskkill.exe /f /im mysqld.exe',wannacryattack).
processArguments('cmd.exe /c start /b @WanaDecryptor@.exe vs',wannacryattack).
processArguments('cmd.exe /c vssadmin delete shadows /all /quiet & wmic shadowcopy delete & bcdedit /set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default} recoveryenabled no & wbadmin delete catalog -q',wannacryattack).
processArguments('-m security',wannacryattack).
processArguments('cmd /c <15 digits>.bat',wannacryattack).
processArguments('cscript.exe //nologo <1 character>.vbs',wannacryattack).
