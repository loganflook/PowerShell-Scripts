<#
    Functions I want to add:
        User gives the remote machine they want to pull data from  <-- this will have to wait until testing in AD Domain
            Enter-PSSession
        User gives the output directory
            Checks to see if directory exists, if it does then it puts files in it, if not it creates them and then puts files in it
        Script runs through a list of information gathering functions and outputs data to TXT or JSON in the output directory
            Each function informs the user that it is gathering the information, gathered successfull or not, displays interesting info, and shows the output path

    Inspiration Sources
        'Hunting and Gathering with PowerShell' - Troy Wojewoda, GSEC Gold Paper - (Data parsing complete)
        'Live Response Using PowerShell' - Sajeev Nair, GCFA Gold Paper
        'Purple Team Field Manual' - Tim Bryant
        'Blue Team Handbook: Incident Response' - Don Murdoch
#>

[CmdletBinding()]
param (
    [Parameter(ValueFromPipeline=$true,Mandatory=$true)]
    [alias('dir','output')]
    [string]$OutputDirectory,
    [switch]$Full=$false
)


Function set-directory {
    # Test if directory exists
    Write-host "`r`n---------------------------------------------------------------------"
    Start-Sleep -seconds 0.5
    Write-Host "Testing if directory exists" -ForegroundColor Yellow
    if (Test-path -Path $OutputDirectory) {
        Start-Sleep -seconds 1
        write-host "Directory found, output will be placed here" -ForegroundColor Green
        New-Item "$OutputDirectory\XML_Files" -ItemType Directory
        write-host "XML File Directory Created" -ForegroundColor Green
        Write-host "---------------------------------------------------------------------`r`n"
    } else {
        Start-Sleep -seconds 1
        write-host "Directory does not Exists!" -ForegroundColor Red -BackgroundColor Black
        Start-Sleep -seconds 1
        Write-Host "Creating Directory" -ForegroundColor Yellow
        New-Item $OutputDirectory -ItemType Directory
        Start-Sleep -seconds 1
        Write-Host "Directory created, output will be placed here" -ForegroundColor Green
        New-Item "$OutputDirectory\XML_Files" -ItemType Directory
        write-host "XML File Directory Created" -ForegroundColor Green
        Write-host "---------------------------------------------------------------------`r`n"
    }
} # Set-Directory

# Below Functions will be ran with default option selected
function Get-LocalAccounts {
    Write-host "Gathering Local Account names" -ForegroundColor Yellow
    Get-CimInstance -classname win32_account -computername localhost | Out-File "$OutputDirectory\Local_Accounts.txt"
    Get-CimInstance -classname win32_account -computername localhost | Export-Clixml -Path "$OutputDirectory\XML_Files\Local_Accounts.xml" -Force
    Write-Host "Local accounts placed in $outputdirectory\localaccounts.txt" -ForegroundColor Green
    Write-host "---------------------------------------------------------------------`r`n"

}
function Get-LoggedInUser { 
    Write-host "Assessing Current Logged in User" -ForegroundColor Yellow
    Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object Name, UserName, PrimaryOwnerName,
    Domain, totalphysicalmemory, Model, manufacturer | Out-File "$OutputDirectory\Logged_in_user.txt"
    Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object Name, UserName, PrimaryOwnerName,
    Domain, totalphysicalmemory, Model, manufacturer | Export-Clixml -Path "$OutputDirectory\XML_Files\Logged_in_user.xml" -Force
    Write-Host "Logged in user information stored in $outputdirectory\Loggedinuser.txt" -ForegroundColor Green
    Write-host "---------------------------------------------------------------------`r`n"

}
function Get-NetworkConnection {
    Write-host "Gathering active TCP connections" -ForegroundColor Yellow
    Get-NetTCPConnection -State Established -AppliedSetting Internet | Select-Object CreationTime, LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess, State `
    | Out-File "$OutputDirectory\Active_TCP_Connections.txt"
    Write-Host "Active TCP connections stored in $outputdirectory\Active_TCP_Connections.txt" -ForegroundColor Green
    Get-NetTCPConnection -State Established -AppliedSetting Internet | Select-Object CreationTime, LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess, State `
    | Export-Clixml -Path "$OutputDirectory\XML_Files\Active_TCP_Connections.xml" -Force
    Write-host "---------------------------------------------------------------------`r`n"  
}
function Get-NetworkShares {
    Write-host "Identifying Network Shares" -ForegroundColor Yellow
    Get-ChildItem "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\" | Select-Object PSChildName | Out-File "$OutputDirectory\Network_Shares.txt"
    Get-ChildItem "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\" | Select-Object PSChildName | Export-Clixml -Path "$OutputDirectory\XML_Files\Network_Shares.xml"
    Write-Host "Active TCP connections stored in $outputdirectory\Network_Shares.txt" -ForegroundColor Green
    Write-host "---------------------------------------------------------------------`r`n"  
}
function Get-RunningProcesses{
    Write-host "Gathering Running Processes" -ForegroundColor Yellow
    Get-Process | Where-Object StartTime -ne $null | Select-Object StartTime, ProcessName, ID, Path | Out-File "$OutputDirectory\Running_Processes.txt"
    Get-Process | Where-Object StartTime -ne $null | Select-Object StartTime, ProcessName, ID, Path | Export-Clixml -Path "$OutputDirectory\XML_Files\Running_Processes.xml"
    Write-Host "Running Processes store in $OutputDirectory\Running_Processes.txt" -ForegroundColor Green
    Write-host "---------------------------------------------------------------------`r`n"  
}
function Get-AutomaticServices {
    Write-host "Detecting automatic services" -ForegroundColor Yellow
    Get-Service | Select-Object Name, DisplayName, Status, StartType | Where-Object StartType -eq "Automatic" | Out-File "$OutputDirectory\Automatic_Services.txt"
    Get-Service | Select-Object Name, DisplayName, Status, StartType | Where-Object StartType -eq "Automatic" | Export-Clixml -Path "$OutputDirectory\XML_Files\Automatic_Services.xml"
    write-host "Automatic Services stored in $OutputDirectory\Automatic_Services.txt" -ForegroundColor Green
    Write-host "---------------------------------------------------------------------`r`n"  
}
function Get-CommandLines {
    Write-Host "Identifying Parent Processes & Command Lines" -ForegroundColor Yellow
    Get-CimInstance -ClassName Win32_Process | Where-Object CommandLine -ne $null | Select-Object CreationDate, ProcessName, ProcessID, CommandLine, ParentProcessId | Out-File "$OutputDirectory\Parent_Processes.txt"
    Get-CimInstance -ClassName Win32_Process | Where-Object CommandLine -ne $null | Select-Object CreationDate, ProcessName, ProcessID, CommandLine, ParentProcessId | Export-Clixml -Path "$OutputDirectory\XML_Files\Parent_Processes.xml"
    write-host "Parent Processes stored in $OutputDirectory\Parent_Processes.txt" -ForegroundColor Green
    Write-host "---------------------------------------------------------------------`r`n"  

}
function Get-ScheduledTasks {
    Write-Host "Identifying Non-Microsoft Scheduled Tasks" -ForegroundColor Yellow
    Get-ScheduledTask | Select-Object TaskName, TaskPath, Date, Author, Actions, Triggers, Description, State `
    | Where-Object Author -NotLike 'Microsoft*' `
    | Where-Object Author -ne $null `
    | Where-Object Author -NotLike '*@%SystemRoot%\*' `
    | Out-File "$OutputDirectory\Non_Microsoft_Scheduled_Tasks.txt"
    Write-Host "Scheduled tasks stored in $OutputDirectory\Non_Microsoft_Scheduled_Tasks.txt" -ForegroundColor Green
    Write-host "---------------------------------------------------------------------`r`n"  
}
function Get-DefaultInfo {
    set-directory
    Get-LocalAccounts
    Get-LoggedInUser
    Get-NetworkConnection
    Get-NetworkShares
    Get-RunningProcesses
    Get-AutomaticServices
    Get-CommandLines
    Get-ScheduledTasks
}
# Below Functions will be ran with -Full option selected, as well as default options
function Get-PsexecEvents {
   Get-WinEvent -FilterHashtable @{ Logname='System'; ID='7045'} | Where-Object {$_.Message.contains("PSEXEC")} | Out-File "$OutputDirectory\PsexecEvents.txt"
  # Write-host "Debugging statement at Get-PsexecEvents" -ForegroundColor Red
}

function Get-FullInfo {
    # Get-DefaultInfo
    set-directory # Remove this once the Get-DefaultInfo is enabled
    Get-PsexecEvents
}
function Get-AutomatedHuntingInfo {
    switch($Full){
        $false {Get-DefaultInfo}
        $true {Get-FullInfo}
    }    
} # Get-Automated Hunting Info



Get-AutomatedHuntingInfo