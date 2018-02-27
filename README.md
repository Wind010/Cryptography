# Cryptography
Wrappers around .NET Cryptographic Service Providers.


## Example Usage
Cryptography.exe GenerateKeys -p PrivateKey.txt -pub PublicKey.txt 

Cryptography.exe Encrypt -pub PublicKey.txt -ue UnEncrypted1.txt -en Encrypted.txt

Cryptography.exe Decrypt -p PublicKey.txt -ue UnEncrypted2.txt -en Encrypted.txt
