# DO NOT USE THIS , PURELY TESTING

$files = Get-ChildItem -Recurse | Where-Object { $_.CreationTime -ge "06/20/2022"}
$i = 0
foreach ($file in $files) {
    Copy-Item -Destination "E:\BuffCompGraphics\LaserBeak Logs\$i$file" 
    $i++
}


#Get-ChildItem -Recurse | Where-Object { $_.CreationTime -ge "06/20/2022"} | Copy-Item -Destination 'E:\BuffCompGraphics\LaserBeak Logs\'
