<#
.SYNOPSIS
    Script to submit IP Addresses to the SANS Internet Storm Center, and retrieve back the number of reports on each IP.
.DESCRIPTION
    Using a text file, this script will retrieve the number of reports that an IP has received from the SANS Internet Storm Center dshield honeypot network.
    Additionally, it will retrieve the number of targeted IPs that a submitted IP has attacked.
.NOTES
    Currently, this script is reserved to text file which have IPs separated on each line.
    I will work on getting it to accept a CSV as well.
.LINK
    N/A
.EXAMPLE
    .\Get-ISCInfo.ps1 -IPAddresses .\IPAddresses.txt
    .\Get-ISCInfo.ps1 -IPs .\IPAddresses.txt
.TODO
    Get Dr. Ullrich's feedback on $UserAgentString and if it works
#>

[CmdletBinding()]
param (
    [Parameter(ValueFromPipeline=$true,Mandatory=$true)]
    [alias('IPs','Addresses')]
    [string]$IPAddresses
)

# The ISC requires API requests to contain contact information (email) as they will sometimes block IPs making too many API calls.
# Change the userId to your contact email address
# $headers = @{
#     'userId' = 'Contact information is joe@testing.com'
# }
$UserAgentString = "Mozilla/5.0 (contact info joe@testing.com) WindowsPowerShell/3.0"

function Get-ISCInfo {
    # Main calling function.
    # Here a foreach loop will take in the content of a supplied TXT file, and loop it through an API request to the ISC website - this is done via the REST API method.
    foreach ($ip in (Get-Content $IPAddresses)) {
        $RequestString = (Invoke-RestMethod -Uri "http://isc.sans.edu/api/ip/$ip" -UserAgent $UserAgentString)
        # Here we rename some of the object properites for easier understanding of the output we receive from the ISC API.
        $RequestString.ip | Select-Object @{N='IP Address';E={$_.Number}}, @{N='Reports';E={$_.Count}}, @{N='Targeted IPs';E={$_.attacks}}, 
        @{N='Country';E={$_.ascountry}}, @{N='ASN';E={$_.as}}, @{N='ASN Name';E={$_.asname}}, @{N='Last Updated';E={$_.updated}}
    }
} # end Get-ISCInfo

# Main function call
Get-ISCInfo