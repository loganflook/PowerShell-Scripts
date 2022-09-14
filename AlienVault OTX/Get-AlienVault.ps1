<#
.SYNOPSIS
    Script to pull IP address reputational score and pulse counts from AlienVault OTX.
.DESCRIPTION
    This is a simple script to pull the IP address reputational score, pulse count, and country ASN of submitted IP addresses from AlienVault OTX.
.NOTES
    Currently, this script is reserved to text file which have IPs separated on each line.
    I will work on getting it to accept a CSV as well.
.LINK
    N/A
.EXAMPLE
    .\Get-AlienOTX.ps1 -IPAddresses .\IPAddresses.txt
#>
[CmdletBinding()]
param (
    [Parameter(ValueFromPipeline=$true,Mandatory=$true)]
    [alias('IPs','Addresses')]
    [string]$IPAddresses
)

# You can look for the following pieces of information on IP address in the RequestURI 
# general, reputation, geo, malware, urlList, passiveDns

function Get-AlienVaultOTXInfo {
    # Enter your API Key here
    $APIKey = "PUT-YOUR-API-KEY-HERE"
    foreach ($ip in (Get-Content $IPAddresses)) {
        # Loop through all IP addresses
        $RequestURI = "https://otx.alienvault.com/api/v1/indicators/IPv4/$ip/general"
        $Result = (Invoke-WebRequest -Uri $RequestURI -UseBasicParsing -Headers @{"X-OTX-API-KEY"="$APIKey"} -UseDefaultCredentials)
        $findings = $Result | ConvertFrom-Json
        # Select the fields we want (IP address, pulse count, score, country)
        $findings | Select-Object @{N='IP Address';E={$_.indicator}}, @{N='Pulse Count';E={$_.pulse_info.count}}, @{N='Reputation Score';E={$_.reputation}}, @{N='Country';E={$_.country_name}}
    }
} # end Get-AlienVaultOTXInfo

# Main function call
Get-AlienVaultOTXInfo