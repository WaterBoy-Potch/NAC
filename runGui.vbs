Set wshShell = CreateObject("WScript.Shell")  ' Create shell object
wshShell.Run """%CLIENT_BATCH%""", 0  ' Run batch silently using path from paths.py
Set wshShell = Nothing                 ' Release shell object