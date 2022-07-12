<#
    This script is a testing script for different information gathering functions.
    It is written up as a 'choose your own adventure' style approach where you can select different queries to run.
    This is not meant to be used in a production environment or for real-world applicability.
#>


$global:IoCsFound = @()


function Get-LocalAccounts {
    $localAccs = Get-CimInstance -classname win32_account -computername localhost
    foreach($i in $localAccs) {write-host $i.Caption}
    Get-IOCs
}
function Get-LoggedInUser { 
    $loggedInUser = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object Name, UserName, PrimaryOwnerName,
    Domain, totalphysicalmemory, Model, manufacturer
    write-host ($loggedInUser | Format-List | Out-String)
    Get-IOCs
}
function Get-NetworkConnection {
    $RemoteHost = Read-Host "Remote host IP (optional)"

    if ($RemoteHost){
        $netCon = Get-NetTCPConnection -RemoteAddress $RemoteHost | Select-Object CreationTime, LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess, State
    } else {
        $netCon = Get-NetTCPConnection -State Established -AppliedSetting Internet| Select-Object CreationTime, LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess, State
    }
    Write-Host ($netCon | Format-List | Out-String)  
}
function Get-NetworkShares {
    $netShares = Get-ChildItem "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\" | Select-Object PSChildName
    Write-Host $netShares
}
function Get-RunningProcesses{
    $ProcessID = Read-Host "Specify a process ID (optional)"
    if ($processID) {
        $procs = Get-Process | Where-Object StartTime -ne $null | Select-Object StartTime, ProcessName, ID, Path | Where-Object Id -eq $ProcessID
    } else {
        $procs = Get-Process | Where-Object StartTime -ne $null | Select-Object StartTime, ProcessName, ID, Path
    }
    Write-Host ($procs | Format-List | Out-String) 
}
function Get-AutomaticServices {
    $autoServices = Get-Service | Select-Object Name, DisplayName, Status, StartType | Where-Object StartType -eq "Automatic"
    Write-Host ($autoServices | Format-List | Out-String) 
}
function Get-ParentProcessesAndCommandLines {
    $ProcessIDForParent = Read-Host "Specify a process ID? Enter ID or no"
    if ($ProcessIDForParent -ne "no") {
        $procAndParentCMD = Get-CimInstance -ClassName Win32_Process | Select-Object CreationDate, ProcessName, ProcessID, COmmandLine, ParentProcessId | Where-Object ProcessID -eq $ProcessIDForParent
    } else {
        $procAndParentCMD = Get-CimInstance -ClassName Win32_Process | Select-Object CreationDate, ProcessName, ProcessID, COmmandLine, ParentProcessId
    }
    
    Write-Host $procAndParentCM
}
function Get-ScheduledTasks {
    $schedTasks = Get-ScheduledTask | Select-Object TaskName, TaskPath, Date, Author, Actions, Triggers, Description, State | where Author -NotLike 'Microsoft*' | where Author -ne $null | where Author -NotLike '*@%SystemRoot%\*'
    $schedTasks
}
function Get-HashOfFile {
    $pathtohash = Read-Host "Enter path to file"
    $fileHash = Get-FileHash $pathtohash -Algorithm SHA256
    Write-Host $fileHash
}
function Get-AlternativeDataStreams {
    $PathToAlternativeDataStream = Read-Host "Enter path to file"
    $ADS = Get-Item $PathToAlternativeDataStream -Stream *
    Write-Host $ADS 
    # Get-Item $PathToAlternativeDataStream * | where Stream -ne ':$DATA'
}
function Get-ADSStreamContent {
    $PathToADSStream = Read-Host "Enterpath to file"
    $StreamName = Read-Host "Enter Stream Name"
    if ($PathToADSStream -and $StreamName) {
        $streamConent = Get-Content $PathToADSStream -Stream $StreamName
        Write-host $streamConent
    } else {
        Write-Host "Error: No file/stream relationship found"
    }
}
function Get-FileAnalysis {
    $filepath = Read-Host "Enter path to file"
    $answer = Read-Host "Do you want the hex format? Enter yes or no"
    if ($answer -eq "yes"){
        $fileContent = get-content $filepath | Format-Hex
    } else {
        $fileContent = get-content $filepath
    }
    Write-Host $fileContent
}
function Get-DecodedData {
    $Base64Data = Read-Host "Enter Base64 string"
    $b64Decoded = [System.Text.Encoding]::ascii.GetString([System.Convert]::FromBase64String($Base64Data))
    $b64Decodedhex = [System.Text.Encoding]::ascii.GetString([System.Convert]::FromBase64String($Base64Data)) | Format-Hex
    
    write-host $b64Decoded
    Write-Host $b64Decodedhex

}
function Get-ParentProcessesAndCommandLines {
$RunningProcesses = Get-CimInstance -classname Win32_Process | `
Select-Object CreationDate, ProcessName, ProcessID, COmmandLine, ParentProcessId

for ($i=0;$i -le $RunningProcesses.count; $i++) {
    Write-host $RunningProcesses[$i]

    Write-Host("Parent")
    Write-Host (Get-CimInstance -ClassName Win32_Process | Where-Object ProcessID -eq $runningprocesses[$i].ParentProcessId).ProcessName
    Write-Host("Parent CmdLine:")
    Write-Host (Get-CimInstance -ClassName Win32_Process | Where-Object ProcessId -eq $runningprocesses[$i].ParentProcessId).CommandLine
    Write-Host("Parent Process Name")
    Write-Host("-----------------------------")
    }
}
function Get-TCPConnectionsAndCommandLines {
        $TCPConns = Get-NetTCPConnection | `
        Select-Object CreationTime, LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess, State

    for($i=0;$i -le $TCPConns.count; $i++) {
        Write-Host $TCPConns[$i]

        Write-Host("Process:")
        Write-Host (Get-CimInstance -classname Win32_Process | Where-Object ProcessId -eq $TCPConns[$i].OwningProcess).ProcessName
        Write-Host("CmdLine:")
        Write-Host (Get-CimInstance -ClassName Win32_Process | Where-Object ProcessId -eq $TCPConns[$i].OwningProcess).CommandLine
        Write-Host("-------------------------")
    }
}
function Get-UDPConnectionsAndCommandLines {
    $UDPConns = Get-NetUDPEndpoint | `
    Select-Object CreationTime, LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess, State

    for ($i=0;$i -le $UDPConns.count; $i++) {
        Write-host $UDPConns[$i]

        Write-Host("Process:")
        Write-Host (Get-CimInstance -ClassName Win32_Process | Where-Object ProcessId -eq $UDPConns[$i].OwningProcess).ProcessName
        Write-Host("CmdLine:")
        Write-Host (Get-CimInstance -classname Win32_Process | Where-Object ProcessId -eq $UDPConns[$i].OwningProcess).CommandLine
        Write-Host("------------------------")
    }
}
function Get-UnusualExecutables {
    $ignore_extensions = '.exe','dll'

    $DirectoryPath = Read-Host "Enter Directory path"
    $directoryFiles = Get-ChildItem $DirectoryPath
    Write-Host("Number of files/folder:")$directoryFiles.count
    $count_suspect = 0

    for ($i=0;$i -lt $directoryFiles.count; $i++) {
        if ( (Test-path $directoryFiles[$i] -PathType Leaf) -and ($directoryFiles[$i].Extension -notin $ignore_extensions)) {
            $magicBytes = '{0:X2}' -f (Get-Content $directoryFiles[$i] -AsByteStream -readcount 4)
            if ($magicBytes -eq '4D 5A 90 00') {
                write-host ("Found atypical file:")$directoryFiles[$i]
                $count_suspect++
            }
        }
    }

    Write-Host("Number of atypical executables found:")$count_suspect
}

function Get-IOCs {
    $FoundIoC = Read-Host "Record any IOC? Yes or No (Default is no)"
    if ($FoundIoC -eq "yes") {
        $IoC = read-host "Type the IOC and any additional information, IOCs can be displayed via Main Menu"
        $Global:IoCsFound += $IoC
    }
}

function Get-IOCList {
    Write-Host $Global:IoCsFound -BackgroundColor black -ForegroundColor Yellow
}

function Invoke-Hunt {
    Write-Host ("welcome")
    $SelectedAdventure = Write-Host "Choose your adventure:
    1: Get local account information
    2: Get Current Logged In User
    3: Get Network Activity
    4: Get Network Shares
    5: Get Running Processes
    6: Get Automatic Services
    7: Get Parent Processes and Command Lines
    8: Get Suspicious Scheduled Tasks
    9: Collect a file's hash
    10: Evaluate file's Alternative Data Stream
    12: Evaluate a file's ADS' Data
    13: Collect a file's content
    14: Decode Base64 String
    15: Get Parent/Child Process Relationships
    16: Get TCP Connections, their processes, and command lines
    17: Get UDP Connections, their processes, and command lines
    18: Get Executable with atypical extensions (anything other than .exe and .dll)
    98: Display Found IoCs
    99: Exit"

    # grab user input
    $SelectedAdventure = read-host
    Switch ($SelectedAdventure) {
        1 {Get-LocalAccounts}
        2 {Get-LoggedInUser}
        3 {Get-NetworkConnection}
        4 {Get-NetworkShares}
        5 {Get-RunningProcesses}
        6 {Get-AutomaticServices}
        7 {Get-ParentProcessesAndCommandLines}
        8 {Get-ScheduledTasks}
        9 {Get-HashOfFile}
        10 {Get-AlternativeDataStreams}
        12 {Get-ADSStreamContent}
        13 {Get-FileAnalysis}
        14 {Get-DecodedData}
        15 {Get-ParentProcessesAndCommandLines}
        16 {Get-TCPConnectionsAndCommandLines}
        17 {Get-UDPConnectionsAndCommandLines}
        18 {Get-UnusualExecutables}
        98 {Get-IOCList}
        99 {Write-Host "Thank you"; Exit} #break out of while loop
    }
} 


while ($true) {
    Invoke-Hunt
}
