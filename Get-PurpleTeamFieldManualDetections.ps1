<#
    Purpose:
        The purpose of this script is to automate the implementation of the different detection mechanisms on a Windows host outlined in the book: Purple Team Field Manual - Tim Bryant
#>

# Detection remote admin tools through command line auditing
function Set-CommandLineAuditing {
    reg add "hklm\software\microsoft\windows\currentversion\policies\system\audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1
}

# Disallow specific executable from executing on a host
# You will need to change the executable name!!
function Set-DisallowedExecutable {
    reg add "hkcu\software\microsoft\windows\currentversion\policies\explorer" /v DisallowRun /t REG_DWORD /d "00000001"
    reg add "hkcu\software\microsoft\windows\currentversion\policies\explorer\disallowrun" /v Evil.exe /t REG_SZ /d Evil.exe /f
}