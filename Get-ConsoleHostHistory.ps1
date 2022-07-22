# DO NOT USE THIS , PURELY TESTING

[CmdletBinding()]
param (
    [Parameter(Mandatory=$True)]
    [string]$ClientDirectory,
    [Parameter(Mandatory=$True)]
    [string]$OutputDirectory
)

function Get-ConsoleHostFile {
    $users = Get-ChildItem "$clientdirectory\users" 
    foreach ($user in $users){
        # This foreach-loop will loop through all identified users in the User folder and run LECmd against their link files
        $PSReadlineDirectory = "$Clientdirectory\Users\$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline"
        Copy-item "$PSReadlineDirectory\ConsoleHost_history.txt" -Destination $OutputDirectory
    }
} # end Get-ConsoleHostFile

Get-ConsoleHostFile