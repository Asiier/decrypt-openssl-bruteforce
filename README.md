#This is a fork with added funcionality and fixing some errors. Bases on thosearetheguise code.

# decrypt-openssl-bruteforce
Basic application to peform a dictionary attack to 'bruteforce' decrypt files encrypted with openssl and save the plain text file locally.

```
usage: decrypt-openssl-bruteforce.py [-h] -i INFILE -w WORDLIST -o OUTFILE -a CIPHERLIST
                                     [-c [CIPHER]] [-s [SALTED]]
                                     [-b64 [BASE64]] [-v [VERBOSE]]
                                     [-vv [VERYVERBOSE]]

decrypt-openssl-bruteforce performs dictionary attacks against openssl encrypted files saving the plain text file locally

optional arguments:
  -h, --help            show this help message and exit

required arguments:
  -i INFILE, --infile INFILE
                        Path to the encrypted file.
  -w WORDLIST, --wordlist WORDLIST
                        Path to the wordlist/dictionary file
  -o OUTFILE, --outfile OUTFILE
                        Path of the plain text output if decrypted.

optional arguments:
  -a [CIPHERLIST], --all [CIPHERLIST]
                          Try all ciphers available in the provided wordlist
                          This is useful if the cipher is also unknown.
  -c [CIPHER], --cipher [CIPHER]
                        Any openssl supported cipher including leading -
                        (openssl enc -ciphers) default: -aes256
  -s [SALTED], --salted [SALTED]
                        Data is encrypted with salt (openssl enc'd data with
                        salted password) default: False
  -b64 [BASE64], --base64 [BASE64]
                        Data is Base64 encoded. Default: False
  -v [VERBOSE], --verbose [VERBOSE]
                        Verbose output, output all passwords atempted.
                        Default: False
  -vv [VERYVERBOSE], --veryverbose [VERYVERBOSE]
                        Very Verbose output, also output the openssl commands
                        executed, (includes -v). Default: False

```
