# Honestly don't know if this is working yet

$url = "https://mxtoolbox.com/api/v1/lookup/blacklist/?argument=70.71.89.187"
$headers = @{
    'Authorization' = "<API KEY>"
}
Invoke-RestMethod -Method GET -Uri $url -Headers $headers