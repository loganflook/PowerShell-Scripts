<#
    Purpose:
        The purpose of this script is to automate the implementation of the different detection mechanisms on a Windows host outlined in the book: Purple Team Field Manual - Tim Bryant

    Note:
        This script is NOT completed
#>

# Detection remote admin tools through command line auditing
function Set-CommandLineAuditing {
    reg add "hklm\software\microsoft\windows\currentversion\policies\system\audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1
}

# Find PSEXEC commands
function Get-PSEXECCommands {
    Get-WinEvent -FilterHashtable @{Logname='System'; ID='7045'} | Where-Object {$_.Message.contains("PSEXEC")}
}

# Disallow specific executable from executing on a host
# You will need to change the executable name!!
function Set-DisallowedExecutable {
    reg add "hkcu\software\microsoft\windows\currentversion\policies\explorer" /v DisallowRun /t REG_DWORD /d "00000001"
    reg add "hkcu\software\microsoft\windows\currentversion\policies\explorer\disallowrun" /v Evil.exe /t REG_SZ /d Evil.exe /f
}

# Enforce Safe DLL Search Mode
function Set-SafeDLLSearchMode {
    reg add "hklm\system\CurrentControlSet\Control\Session Manager" /v SafeDllSearchMode /t REG_DWORD /d 1
}

# Restrict access to registry editor
function Set-RegistryEditorRestriction {
    reg add "hkcu\software\microsoft\windows\currentversion\policies\system" /v DisableRegistryTools /t REG_DWORD /d 2
}