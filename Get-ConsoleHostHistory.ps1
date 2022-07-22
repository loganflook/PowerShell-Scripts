<#
.SYNOPSIS
    Short script to put any ConsoleHost_history.txt files that are in user directories.
.DESCRIPTION
    This script will check all users found in a give directory for the presence of the ConsoleHost_history.txt file in the default PSReadline path. 
    This text file holds recent PowerShell commands that a user has ran in the past, if said user did not mannually delete the file.
    Pulling these files can be a quick reference to see if any user(s) have been executing commands in PowerShell.
.NOTES
    ConsoleHost_history.txt is an artifact that can be manipulated and deleted by users without the need for administrator privileges. As such this file SHOULD NOT be used as a sole
    indicator of compromise or lack thereof.
.LINK
    N/A
.EXAMPLE
    .\Get-ConsoleHostHistory.ps1 -UserDirectory C:\Users -OutputDirectory D:\Evidence\Case1\
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$True)]
    [string]$UserDirectory,
    [Parameter(Mandatory=$True)]
    [string]$OutputDirectory
)

function Get-ConsoleHostFile {
    # Get the user names for every user in the given directory.
    $users = (Get-ChildItem $UserDirectory).Name
    # Loop through each user
    foreach ($user in $users){
        # Establish the path to the ConsoleHost_history.txt file
        $PSReadlineDirectory = "$UserDirectory\$User\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline"
        if (Test-Path $PSReadlineDirectory) {
            # If the file exists - aka if the user has been using PowerShell and has not manipulated the artifact - copy the file to the output directory.
            Write-Host "PSReadline folder exists for user: $user. Copying file" -ForegroundColor Yellow
            Copy-Item "$PSReadlineDirectory\ConsoleHost_history.txt" -Destination "$OutputDirectory\ConsoleHistory_of_$user.txt"
            Write-Host "ConsoleHistory file for user: $user has been copied to the specified output directory." -ForegroundColor Green
        } else {
            # Notify which users do not have a PSReadline folder.
            Write-Host "PSReadline folder does not exist for user: $User" -ForegroundColor Red
        }
    }
} # end Get-ConsoleHostFile

# Main function call
Get-ConsoleHostFile