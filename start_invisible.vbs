Set WshShell = CreateObject("WScript.Shell")
scriptPath = CreateObject("Scripting.FileSystemObject").GetParentFolderName(WScript.ScriptFullName)
WshShell.Run chr(34) & scriptPath & "\start_complete_application.bat" & Chr(34), 0
Set WshShell = Nothing
