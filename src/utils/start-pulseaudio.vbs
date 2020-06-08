Set shell = WScript.CreateObject("WScript.Shell")
scriptdir = CreateObject("Scripting.FileSystemObject").GetParentFolderName(WScript.ScriptFullName)
target = scriptdir & "\pulseaudio.exe "
Set myArgs = WScript.Arguments.Unnamed

For i = 0 to myargs.count - 1
    target = target & """" & myArgs.item(i) & """ "
Next

Const HIDDEN_WINDOW = 0

Set objWMIService = GetObject("winmgmts:\\.\root\cimv2")
Set objStartup = objWMIService.Get("Win32_ProcessStartup")
Set objConfig = objStartup.SpawnInstance_
objConfig.ShowWindow = HIDDEN_WINDOW
Set objProcess = GetObject("winmgmts:\\.\root\cimv2:Win32_Process")
objProcess.Create target, null, objConfig, intProcessID
