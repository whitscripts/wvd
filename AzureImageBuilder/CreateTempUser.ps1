$password = 'P@ssw0rd.1234!' | ConvertTo-SecureString -asPlainText -Force
New-LocalUser "imagebuilder" -Password $Password -FullName "Image Builder" -Description "Temp Account to Install Sepago"
Add-LocalGroupMember -Group "Administrators" -Member "imagebuilder"