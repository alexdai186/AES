UTEID: amd4482; scw2243;
FIRSTNAME: Alexander; Songting
LASTNAME: Dai; Wu;
CSACCOUNT: alexdai; cindywu;
EMAIL: alexdai@utexas.edu; cindywu2018@utexas.edu;

[Program 5]
[Description]
There is only 1 java file named AES.java. In this main file, we implemented the AES-256 encryption. First we created the state, which is an int[][] matrix, then we converted the cipherkey from a giant string to an int[][] matrix as well. Next, we expanded this cipher key to a 4x60 int[][] matrix with the method expandKey(). 
Now with the appropriate data structures in place, we are ready to encode/decode. Inside encode(), we first perform an addRoundKey(0) before the rounds begin, then 13 FULL rounds of encryption, where each round starts with subBytes(), shiftRows(), mixColumns(), and addRoundKey(i). Finally, in the 14th round, we don't perform mixColumns but do perform the other 3 methods. 
Decode() is literally the inverse of encoding, where we start with addRoundKey(14), invShiftRows(), invSubBytes() to reverse the last round of encryption. Then we will do the 13 FULL rounds of decryption, where each round starts with addRoundKey(i), invMixColumns(), invShiftRows(), and invSubBytes(). Notice that those methods are inverse of their encryption counterparts, and done in reverse order. Finally, for the last round of decryption, we will undo the addRoundKey(0) done in encryption before the encryption rounds started, to fully retrieve the original plaintext.
Below are functionalities of each main functions:
1) subBytes() performs substitution by replacing all values in state with values from sBox[][], and invSubBytes() replaces all values in state with values from invSBox[][]. They cancel each other out so the original plaintext can be retrieved.
2) shiftRows() shifts the last three rows of state to the left, while invShiftRows() shifts the last three rows of state to the right. 
3) mixColumns performs matrix operation on the state and replaces each byte of the column with a bit-wise XOR to a lookup table. For invMixColumns(), the test vectors are simply reversed.
4) addRoundKey() performs a bit-wise XOR between the state and expanded key.
Finally, the speed in ms of our encoding/decoding functions are timed.
****Note that we used Professor Young's code for mixColumns() and consulted the Rijndael book on key expansion. We have credited every source inside our java file. 

[Finish]
We finished everything. The final decrypted file matches exactly with the original plaintext.

[Test Case 1]

[Command line]
Encryption: java AES e key plaintext1
Decryption: java AES d key plaintext1.enc

[Timing Information]
Encryption: 32ms
Decryption: 28ms

[Input Filenames]
key, plaintext

[Output Filenames]
Encryption: plaintext1.enc
Decryption: plaintext1.enc.dec

[Test Case 2]

[Command line]
Encryption: java AES e key plaintext2
Decryption: java AES d key plaintext2.enc

[Timing Information]
Encryption: 56ms
Decryption: 35ms

[Input Filenames]
key, plaintext2

[Output Filenames]
Encryption: plaintext2.enc
Decryption: plaintext2.enc.dec

[Test Case 3]

[Command line]
Encryption: java AES e key plaintext3
Decryption: java AES d key plaintext3.enc

[Timing Information]
Encryption: 48ms
Decryption: 71ms

[Input Filenames]
key, plaintext3

[Output Filenames]
Encryption: plaintext3.enc
Decryption: plaintext3.enc.dec

[Test Case 4]

[Command line]
Encryption: java AES e key plaintext4
Decryption: java AES d key plaintext4.enc

[Timing Information]
Encryption: 38ms
Decryption: 41ms

[Input Filenames]
key, plaintext4

[Output Filenames]
Encryption: plaintext4.enc
Decryption: plaintext4.enc.dec