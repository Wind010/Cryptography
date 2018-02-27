# Cryptography
Wrappers around .NET Cryptographic Service Providers.


Example Usage:
GenerateKeys -p C:\Temp\PrivateKey.txt -pub C:\Temp\PublicKey.txt 
Encrypt -pub C:\Temp\PublicKey.txt -ue C:\Temp\UnEncrypted1.txt -en C:\Temp\Encrypted.txt
Decrypt -p C:\Temp\PublicKey.txt -ue C:\Temp\UnEncrypted2.txt -en C:\Temp\Encrypted.txt
