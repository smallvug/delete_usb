Set fso = CreateObject("Scripting.FileSystemObject")
Set shell = CreateObject("Shell.Application")
scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)
shell.ShellExecute "pythonw", """" & scriptDir & "\main.py""", scriptDir, "runas", 1
