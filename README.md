# CS-3750 - Project 1
by Matthew Williams

## Description

Option 2: symmetric-key encrypted message and its digital signature

- In this option, X is the sender and Y is the receiver. 

- In the sender’s program in the directory “Sender”, calculate AES-En Kxy (RSA-En Kx– (SHA256 (M)) || M) bytes long. 

  1. To test this program, the corresponding key files need to be copied here from the directory “KeyGen”

  2. Read the information on the keys to be used in this program from the key files and generate Kx – and Kxy.
  
  3. Display a prompt “Input the name of the message file:” and take a user input from the keyboard. This
     user input provides the name of the file containing the message M. M can NOT be assumed to be a text message. The
     size of the message M could be much larger than 32KB.
  
  4. Read the message, M, from the file specified in Step 3 piece by piece, where each piece is recommended to be a small
     multiple of 1024 bytes, calculate the SHA256 hash value (digital digest) of the entire message M, i.e., SHA256(M), SAVE
     it into a file named “message.dd”, and DISPLAY SHA256(M) in Hexadecimal bytes.
  
     1. An added feature for testing whether the receiver’s program can handle the case properly when the digital digest
        calculated in Step 6 (the receiver’s program) is different from the digital digest obtained in Step 5 (the receiver’s
        program): After calculating SHA256(M) but before saving it to the file named “message.dd” (the sender’s program),
        display a prompt “Do you want to invert the 1st byte in SHA256(M)? (Y or N)”,
        
        1. If the user input is ‘Y’, modify the first byte in your byte array holding SHA256(M) by replacing it with its bitwise
           inverted value (hint: the ~ operator in Java does it), complete the rest of Step 4 by SAVING & DISPLAYING the
           modified SHA256(M), instead of the original SHA256(M), and continue to Step 5 (also use the modified
           SHA256(M), instead of the original SHA256(M), in Steps 5 & 6).
           
        2. Otherwise (if the user input is ‘N’), make NO change to the byte array holding SHA256(M), complete the rest of
           Step 4 (SAVE and DISPLAY), and continue to Step 5.
           
  5. Calculate the RSA Encryption of SHA256(M) using Kx – (Question: how many bytes is the cyphertext?), SAVE this RSA
     cyphertext (the digital signature of M), into a file named “message.ds-msg”, and DISPLAY it in Hexadecimal bytes.
     APPEND the message M read from the file specified in Step 3 to the file “message.ds-msg” piece by piece.
     
  6. Calculate the AES Encryption of (RSA-En Kx– (SHA256 (M)) || M) using Kxy by reading the file “message.ds-msg” piece
     by piece, where each piece is recommended to be a multiple of 16 bytes long. (Hint: if the length of the last piece is less
     than that multiple of 16 bytes, it needs to be placed in a byte array whose array size is the length of the last piece before
     being encrypted.) SAVE the resulting blocks of AES ciphertext into a file named “message.aescipher”.
- In  the  receiver’s  program  in  the  directory  “Receiver”,  using  AES  and  RSA Decryptions to  get  SHA256 (M)  and  M,  compare SHA256(M) with the locally calculated SHA256 hash of M, report hashing error if any, and then save M to a file.

## Running the Program

To start the programs use the following commands:

> java """"  
> java """"  

Once started the program will ...

Additionally, if you want to save the programs outputs to a file the following
commands can be used:

> java """" | tee filename.txt  
> java """" | tee filename.txt  

## Compiling the Program

If the program needs to be compiled use the following commands:

> javac """"  
> javac """"  