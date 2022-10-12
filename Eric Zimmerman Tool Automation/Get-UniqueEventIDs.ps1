<#
.SYNOPSIS
    Script to automate the extracting of dozens of identified interesting events from the log output from Get-EricZimmermanToolAnalysis.
.DESCRIPTION
    This is a second-stage script that can be ran after running the main Get-ErizZimmermanToolAnalysis script.
    It will parse through the CSV logs and extract interesting EventIDs.
    Most of these EIDs are pulled directly off of the SANS Hunt Evil poster, as well as some from personal experience.
    This script can be expanded on to suit your direct needs.
.NOTES
    This script is built specifically to run against the CSV files outputted by the main Get-EricZimmermanToolAnalysis script.
    It will not work when ran againt other data...
    It is also meant to parse the logs and output its results in the SAME folder. This is done to keep all logs together, but could be changed should you like to customize.
.LINK
    N/a
.EXAMPLE
    .\Get-UniqueEventIDs.ps1 -LogLocation "C:\Evidence"
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory=$True)]
    [alias('LogLocation')]
    [string]$LogDirectory
)

function Get-Events() {
    # Parse each log for 'interesting' EIDs and export to a CSV file
    # SYSTEM EIDs
    import-csv "$LogDirectory\System_Logs.csv" | Where-Object  {$_.eventID -eq 7045 -or $_.eventID -eq 7034 -or $_.eventID -eq 7035 -or $_.eventID -eq 7036 -or $_.eventID -eq 7040} | Export-Csv $LogDirectory\ToMergeSystemEventIDs.csv -NoTypeInformation

    # SECURITY EIDs
    import-csv "$LogDirectory\Security_Logs.csv" | Where-Object  {$_.eventID -eq 4648 -or $_.eventID -eq 4624 -or $_.eventID -eq 4778 -or $_.eventID -eq 4779 -or $_.eventID -eq 4672 -or $_.eventID -eq 4776 -or $_.eventID -eq 5140 -or $_.eventID -eq 4698 -or $_.eventID -eq 4702 -or $_.eventID -eq 4720 -or $_.eventID -eq 4722 -or $_.eventID -eq 4699 -or $_.eventID -eq 4700 -or $_.eventID -eq 4701 -or $_.eventID -eq 4697 -or $_.eventID -eq 1102} | Export-Csv $LogDirectory\ToMergeSecurityEventIDs.csv -NoTypeInformation

    # RDP EIDs
    import-csv "$LogDirectory\Microsoft-Windows-TerminalServices-RDPClient%4Operational_Logs.csv" | Where-Object  {$_.eventID -eq 1024 -or $_.eventID -eq 1102} | Export-Csv $LogDirectory\ToMergeRDP1EventIDs.csv -NoTypeInformation
    import-csv "$LogDirectory\Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational_Logs.csv" | Where-Object  {$_.eventID -eq 1149} | Export-Csv $LogDirectory\ToMergeRDP2EventIDs.csv -NoTypeInformation
    import-csv "$LogDirectory\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational_Logs.csv" | Where-Object  {$_.eventID -eq 21 -or $_.eventID -eq 22 -or $_.eventID -eq 25 -or $_.eventID -eq 41} | Export-Csv $LogDirectory\ToMergeRDP3EventIDs.csv -NoTypeInformation
    import-csv "$LogDirectory\Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational_Logs.csv" | Where-Object  {$_.eventID -eq 131 -or $_.eventID -eq 98} | Export-Csv $LogDirectory\ToMergeRDP4EventIDs.csv -NoTypeInformation

    # NETWORK SHARE ACCESS EIDs
    import-csv "$LogDirectory\Microsoft-Windows-SmbClient%4Security_Logs.csv" | Where-Object  {$_.eventID -eq 31001} | Export-Csv $LogDirectory\ToMergeSMBEventIDs.csv -NoTypeInformation

    # SCHEDULED TASK EIDs
    import-csv "$LogDirectory\Microsoft-Windows-TaskScheduler%4Operational_Logs.csv" | Where-Object  {$_.eventID -eq 106 -or $_.eventID -eq 120 -or $_.eventID -eq 141 -or $_.eventID -eq 200 -or $_.eventID -eq 201} | Export-Csv $LogDirectory\ToMergeScheduledTaskEIDs.csv -NoTypeInformation

    # WMIC EIDs
    import-csv "$LogDirectory\Microsoft-Windows-WMI-Activity%4Operational_Logs.csv" | Where-Object  {$_.eventID -eq 5857 -or $_.eventID -eq 5860 -or $_.eventID -eq 5861} | Export-Csv $LogDirectory\ToMergeWMICEventIDs.csv -NoTypeInformation

    # PowerShell EIDs
    import-csv "$LogDirectory\Microsoft-Windows-WinRM%4Operational_Logs.csv" | Where-Object  {$_.eventID -eq 6 -or $_.eventID -eq 8 -or $_.eventID -eq 15 -or $_.eventID -eq 16 -or $_.eventID -eq 33 -or $_.eventID -eq 91 -or $_.eventID -eq 168} | Export-Csv $LogDirectory\ToMergePS1EventIDs.csv -NoTypeInformation
    import-csv "$LogDirectory\Microsoft-Windows-PowerShell%4Operational_Logs.csv" | Where-Object  {$_.eventID -eq 4103 -or $_.eventID -eq 4104 -or $_.eventID -eq 53504} | Export-Csv $LogDirectory\ToMergePS2EventIDs.csv -NoTypeInformation

} # end Get-UniqueEventIDs

function Get-MergedFolder {
    # Merge all new files into one CSV
    # MERGE
    Get-ChildItem -Filter ToMerge*.csv -Path $LogDirectory | Select-Object -ExpandProperty FullName | import-csv | export-csv $LogDirectory\UniqueEventIDs.csv -NoTypeInformation -append 

} # end Get-MergedFolder

function Get-CleanFolder {
    # Clean up the previously used files to keep the folder organized
    Remove-Item $LogDirectory\ToMerge*
} # end Get-CleanFolder

function Get-UniqueEventIDs {
    Get-Events
    Get-MergedFolder
    Get-CleanFolder
} # end Get-UniqueEventIDs

# Main function call
Get-UniqueEventIDs