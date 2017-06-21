$getdomain = [System.Directoryservices.Activedirectory.Domain]::GetCurrentDomain()
$getdomain | ForEach-Object {$_.DomainControllers} | 
ForEach-Object {
  $hEntry= [System.Net.Dns]::GetHostByName($_.Name)
  New-Object -TypeName PSObject -Property @{
      Name = $_.Name
      IPAddress = $hEntry.AddressList[0].IPAddressToString
     }
} | Export-CSV "C:\ControllersList.csv" -NoTypeInformation -Encoding UTF8 
