' WAF monitor background launcher (no window, detached from terminal session)
Set fso = CreateObject("Scripting.FileSystemObject")
Set ws = CreateObject("WScript.Shell")
ws.CurrentDirectory = fso.GetParentFolderName(WScript.ScriptFullName)
ws.Run "cmd /c chcp 65001 >nul & node server.js >> server.log 2>&1", 0, False
