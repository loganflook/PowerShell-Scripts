<#
.SYNOPSIS
    Short script to rename all the files in each folder within a given directory.
.DESCRIPTION
    This is mainly helpful if you have many different subdirectories that all have files that are the same name. This can happen in different logging
    solutions where each folder is unique but the log files therein have the same naming conventions as the other folders. This prevents the ability to easily
    pull all files out of the subdirectories and put them in one place due to having files of the same name.

    This script will essentially move folder to folder and replace a common character (defaulting to 'u') with a number - said number changes for every folder.
    This will now give every file a unique name, and then can be placed with all other log files.
.NOTES
    This is not a super normal occurance and therefore this script is not extremely functional.
.LINK
    N/A
.EXAMPLE
    .\Set-NewFileName.ps1 -$LogPath
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$True)]
    [string]$LogPath
)

# Gather the list of all folders in the given path
$folders = Get-ChildItem -Path $LogPath
# Initialize the I variable later used
$i = 0

# Loop through each folder
foreach ($folder in $folders){
    # First off, get every item (file) in a folder, then rename that folder by replacing the 'u' with the number currently stored in $i
    get-childitem $folder | Rename-Item -NewName {$_.name -replace "u","$i"} # You can change 'u' to anything!
    # Once all the files in one folder are renamed, iterate $i by one, now the next folder's $i will be one greater thereby creating unique file names
    $i++
}