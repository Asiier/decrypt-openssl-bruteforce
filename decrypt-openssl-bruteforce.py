#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Version 2.0 by Asiier

import subprocess
import sys
import os
import string
import argparse

PWD = os.getcwd()

green = "\033[1;32;40m"
normal = "\033[0;37;40m"

def cmdline(command):
    proc = subprocess.Popen(str(command), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    (out, err) = proc.communicate()
    return out

def str2bool(v):
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Bool (true/false) value expected.')

def choice():
    yes = {'yes', 'y', 'ye', ''}
    no = {'no', 'n'}

    print("Do you want to continue with the rest of the list?")
    choice = input().lower()
    if choice in yes:
        return False
    elif choice in no:
        return True
    else:
        sys.stdout.write("Please respond with 'yes' or 'no'")

def bruteforce(cipher,wl_line,cl_line):
    if verbose:
        print("Trying password: {}".format(wl_line))
    if (listciphers is not None):
        cipher = cl_line
    cmd = "openssl enc -d -{}".format(cipher) + ['', ' -base64'][b64] + ['', ' -salt'][salted] + " -in {} -k {}".format(encryptedfile, wl_line)
    unencrypt = cmdline(cmd)
    utf8 = False
    try:
        unencrypt = unencrypt.decode("utf-8")
        for i in unencrypt:
            if i in string.printable:
                utf8 = True
            else:
                utf8 = False
                break
    except UnicodeDecodeError:
        utf8 = False
    if veryverbose:
        print("\nFull command: {}".format(cmd))
        print("Decrypted text: ", end='')
        print(unencrypt)
    if utf8:
        print(green + "Posible Key Found! The key is:{}".format(wl_line))
        print(green + "Using Cipher:{}".format(cipher))
        if outputfile is not None:
            print(normal + "Output File Name : {}".format(outputfile))
            with open(outputfile, 'w') as f:
                print(unencrypt, file=f)
        else:
            print("Decrypted text: " + unencrypt)
        if choice():
            sys.exit()

def main():

    if (len(sys.argv) > 1):

            parser = argparse.ArgumentParser()

            parser = argparse.ArgumentParser(description='decrypt-openssl-bruteforce performs dictionary attacks against openssl encrypted files saving the plain text file locally')
            requiredNamed = parser.add_argument_group('required named arguments')
            requiredNamed.add_argument("-i","--infile", help="Path to the encrypted file.",required=True)
            requiredNamed.add_argument("-w","--wordlist", help="Path to the wordlist file",required=True)
            optionalNamed = parser.add_argument_group('optional arguments')
            optionalNamed.add_argument("-c","--cipher",nargs='?', help="Any openssl supported cipher (openssl enc -ciphers) including the leading '-' default: -aes256",default="-aes256")
            optionalNamed.add_argument("-a","--all",nargs='?', help="Path of the ciphers list to try.")
            optionalNamed.add_argument("-o","--outfile", help="Path of the plain text output if decrypted.")
            optionalNamed.add_argument("-s","--salted",type=str2bool, nargs='?', const=True, default=False, help="Data is encrypted with salt (openssl enc'd data with salted password) default: False")
            optionalNamed.add_argument("-b64","--base64",type=str2bool, nargs='?', const=True, default=False, help="Data is Base64 encoded. Default: False")
            optionalNamed.add_argument("-v","--verbose",type=str2bool, nargs='?', const=True, default=False, help="Verbose output, output all passwords atempted. Default: False")
            optionalNamed.add_argument("-vv","--veryverbose",type=str2bool, nargs='?', const=True, default=False, help="Very Verbose output, also output the openssl commands executed, (includes -v). Default: False")

            global args, salted, b64, verbose, veryverbose, encryptedfile, wordlist, listciphers, wordlist, cipher, outputfile, utf8

            args = parser.parse_args()
            salted = args.salted
            b64 = args.base64
            verbose = args.verbose
            veryverbose = args.veryverbose
            if veryverbose:
                verbose = veryverbose
            encryptedfile = args.infile
            wordlist = args.wordlist
            listciphers = args.all
            cipher = args.cipher
            if listciphers is not None:
                cipher = "List mode"
            print("OpenSSL Decryptor v2.0 by Asiier\nOptional argument values:\n   Salted: {} \n   base64: {} \n   cipher: {}".format(salted, b64,cipher))
            outputfile = args.outfile

            with open(wordlist) as f:
                wl_line = f.readline()
                cl_line = "-aes256"
                i = 1
                if (listciphers is not None):
                       while wl_line:
                           wl_line = wl_line.strip()
                           with open(listciphers) as l:
                               cl_line = l.readline()
                               k = 1
                               while cl_line:
                                    cl_line = cl_line.strip()
                                    if len(wl_line) > 0:
                                        bruteforce(cipher,wl_line,cl_line)
                                    cl_line = l.readline()
                                    k += 1
                           wl_line = f.readline()
                           i += 1
                else:
                   while wl_line:
                        wl_line = wl_line.strip()
                        if len(wl_line) > 0:
                            bruteforce(cipher,wl_line,cl_line)
                        wl_line = f.readline()
                        i += 1
            print(" \nDone.\nThe password might not be in the worlist\nor the cipher(s) used are not the correct one(s)")

    else:
        print ("Usage {} [-h] -i ENCRYPTEDFILE -w WORDLIST -o OUTFILE -a CIPHERSLIST \n[-c CIPHER] [-s SALTED] [-b64 BASE64DECODE]".format(sys.argv[0]))
if __name__ == '__main__':
    main()
