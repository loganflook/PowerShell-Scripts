<#
.SYNOPSIS
    Script to automate several Eric Zimmerman tools for analysis.
.DESCRIPTION
    This script is used to run several Eric Zimmerman tools on a forensic drive mounted to the system.
    Tools included are: PECmd, RECmd, LECmd, JLECmd, RBCmd, AppCompatCacheParser, AmcacheParser, and Evtxcmd.

    Mandatory parameters are the mounted evidence drive, output directory, and directory of the Eric Zimmerman tools. See examples for recommended 
    Paths DO NOT need the final '\', I.E. "G:" and NOT "G:\"
.NOTES
    Evidence must be mounted as the script is pointed towards a drive letter (supplied as an argument). I.E. "E:"
.LINK
    N/a
.EXAMPLE
    .\Get-EricZimmermanToolAnalysis.ps1 -ClientDirectory "G:" -OutputDirectory "C:\OutputDirectory" -EZToolDirectory "C:\EZTools"
    .\Get-EricZimmermanToolAnalysis.ps1 -Source "G:" -Destination "C:\OutputDirectory" -EZDirectory "C:\EZTools"
#>



[CmdletBinding()]
param (
    [Parameter(Mandatory=$True)]
    [alias('Evidence','Source')]
    [string]$ClientDirectory,
    [Parameter(Mandatory=$True)]
    [alias('Output','Destination')]
    [string]$OutputDirectory,
    [Parameter(Mandatory=$True)]
    [alias('EZDirectory')]
    [string]$EZToolDirectory
)

function Get-InputValidation {
    if ($ClientDirectory) {
        Write-Host "Checking to see if evidence path exists"
        if (!(Test-Path $ClientDirectory)){
            Write-Host "WARNING! Evidence path does not exist, exiting script!" -ForegroundColor Red -BackgroundColor Black
            Break
        }
        else {
            Write-Host "Evidence path found. Continuing script"    
        }
    } 
    if ($OutputDirectory) {
        Write-Host "Checking to see if output directory path exists"
        if (!(Test-Path $OutputDirectory)){
            Write-Host "WARNING! Output directory does not exist" -ForegroundColor Yellow -BackgroundColor Black
            Write-Host "Creating directory: $OutputDirectory" -ForegroundColor DarkYellow
            mkdir $OutputDirectory -Force
            Write-Host "Continuing script" -ForegroundColor Yellow
        } else{
            Write-Host "Output directory found. Continuing script"
        }
    } 
} 

function Get-Prefetch{
    # This is the PECmd function. It utilizes PECmd.exe to analyze Windows Prefetch files
    $prefetchDirectory = "$clientDirectory\Windows\Prefetch"
    $pecmd = "$EZToolDirectory\PECmd.exe -d $prefetchdirectory --csv $OutputDirectory -q" 
    Invoke-Expression -Command $pecmd
}

function Get-RECmd {
    # This is the RECmd function. It utilizes RECmd.exe to analyze registry hives
    $hivedirectory = "$clientdirectory\"
    # BatchFilesToRun is a set of batch files found in the 'BatchExamples' folder within RECmd. You can add additional files below
    $BatchFilesToRun = "Logan_UserActivityAuditing.reb","Logan_SystemAuditing.reb"
    foreach ($file in $BatchFilesToRun){
        $RECmdBatchFile = "C:\Tools\EZTools\RECmd\BatchExamples\$file"
        $recmd = "C:\Tools\EZTools\RECmd\RECmd.exe --bn $recmdbatchfile -d $hivedirectory --csv $outputdirectory"
        Invoke-Expression -Command $recmd
    }
}

function Get-RBCmd {
    # This is the RBCmd function. It utilizes RBCmd.exe to analyze the Recycle bin
    $RecycleBinPath = "$ClientDirectory\" + '`$' + "Recycle.bin"
    $rbcmd = "C:\Tools\EZTools\RBCmd.exe -d $Recyclebinpath --csv $outputdirectory"
    Invoke-Expression -Command $rbcmd
}
function Get-AppCompat {
    # This is the AppCompatCache function. It utilizes AppCompatCacheParser to analyze AppCompat data
    $AppCompatDirectory = "$clientdirectory\Windows\System32\config\SYSTEM"
    $appcompatcacheparser = "C:\Tools\EZTools\AppCompatCacheParser.exe -f $AppCompatDirectory --csv $OutputDirectory"
    Invoke-Expression -Command $appcompatcacheparser
}

function Get-AmCache {
    # This is the AmCache function. It utilizes the AmCacheParser to analyze the Amcache hive.
    $Amcachedirectory = "$clientdirectory\Windows\AppCompat\Programs\Amcache.hve"
    $amcacheparser = "C:\Tools\EZTools\AmcacheParser.exe -i -f $amcachedirectory --csv $outputdirectory"
    Invoke-Expression -Command $amcacheparser
}

function Get-WindowsLogs {
    # This is the Evtxecmd function. This utilizes EvtxECmd.exe to parse Windows Logs
    # In the logs variable you can add, or subtract, which log files you want to analyze. 
    # Most of these logs were taken from the SANS Hunt Evil DFIR poster
    $logs = "Security","System","Application","Microsoft-Windows-PowerShell%4Admin",
    "Microsoft-Windows-PowerShell%4Operational","Microsoft-Windows-TerminalServices-RDPClient%4Operational",
    "Microsoft-Windows-SmbClient%4Security","Microsoft-Windows-WinRM%4Operational",
    "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational",
    "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational",
    "Microsoft-Windows-TaskScheduler%4Operational","Microsoft-Windows-WMI-Activity%4Operational",
    "Windows PowerShell"
    foreach ($log in $logs){
        # This foreach-loop will loop through all identified log files in the 'log' variable and run Evtxecmd against them
        $WindowsLogs = "$clientdirectory\Windows\system32\winevt\logs\$log.evtx"
        $Evtxecmd = "C:\Tools\EZTools\EvtxECmd\EvtxECmd.exe -f $WindowsLogs --csv $outputdirectory --csvf " + $log + "Logs.csv"
        Invoke-Expression -Command $Evtxecmd
    }
}

function Get-LECmd {
    # This is the LECmd function. It utilizes LECmd.exe to analyze Link files
    $users = Get-ChildItem "$clientdirectory\users" 
    foreach ($user in $users){
        # This foreach-loop will loop through all identified users in the User folder and run LECmd against their link files
        $LinkFileDirectory = "$Clientdirectory\Users\$user\AppData\Roaming\Microsoft\Windows\Recent"
        $lecmd = "C:\Tools\EZTools\LECmd.exe -d $linkfiledirectory --csv $outputdirectory -q"
        Invoke-Expression -Command $lecmd
    }
}

function Get-JLECmd {
    # This is the JLECmd function. It utilizes JLECmd.exe to analyze jumplist files
    $users = Get-ChildItem "$clientdirectory\users"
    foreach ($user in $users){
        # This foreach-loop will loop through all identified users in the User folder and run JLECmd against their jumplist files
        $JumplistDirectory = "$clientdirectory\users\$user\AppData\Roaming\Microsoft\Windows\Recent"
        $jlecmd = "C:\Tools\EZTools\JLECmd.exe -d $jumplistdirectory --csv $outputdirectory -q"
        Invoke-Expression -Command $jlecmd
    }
}


function Get-ToolAnalysis {
    # This is the primary function call.
    # You can comment out functions (and in turn tools) that you do not want to run.
    Get-InputValidation
    Get-Prefetch
    # Get-RECmd
    # Get-AppCompat
    # Get-AmCache
    # Get-LECmd
    # Get-WindowsLogs
    # Get-JLECmd
    # Get-RBCmd

    Write-Host "Script complete" -ForegroundColor Green
}
# The primary funciton call
Get-ToolAnalysis