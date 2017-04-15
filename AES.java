import java.io.*;
import java.util.*;

public class AES {
	// Nb = 4, Nk = 8, Nr = 14
	private static int[][] state = new int[4][4]; // 128 bit input, in a 4x4 array as INTS
	private static int[][] keyMatrix = new int[4][8];
	private static int[][] expandedKey = new int[4][60]; // W[4][Nb*(Nr+1)]
	// Source: http://cryptography.wikia.com/wiki/Rijndael_S-box
	public final static int[][] sBox = {
		/*0*/{0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
		/*1*/{0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0}, 
		/*2*/{0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15}, 
		/*3*/{0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75}, 
		/*4*/{0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84}, 
		/*5*/{0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
		/*6*/{0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
		/*7*/{0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
		/*8*/{0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
		/*9*/{0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
		/*10*/{0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
		/*11*/{0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
		/*12*/{0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
		/*13*/{0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
		/*14*/{0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
		/*15*/{0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}};
	
	// Source: http://cryptography.wikia.com/wiki/Rijndael_S-box
	public final static int[][] invSBox = {
		{0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb}, 
		{0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb}, 
		{0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e}, 
		{0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25}, 
		{0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92}, 
		{0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84}, 
		{0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06}, 
		{0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b}, 
		{0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73}, 
		{0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e}, 
		{0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b}, 
		{0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4}, 
		{0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f}, 
		{0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef}, 
		{0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61}, 
		{0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}};
	
	// Source: https://en.wikipedia.org/wiki/Rijndael_key_schedule#Rcon
	// For key expansion
	public final static int[] rcon = {
		0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
		0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
		0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
		0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
		0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
		0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
		0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
		0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
		0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
		0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
		0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
		0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
		0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
		0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
		0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
		0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d};
	
	public final static int[] LogTable = {
		0, 0, 25, 1, 50, 2, 26, 198, 75, 199, 27, 104, 51, 238, 223, 3, 
		100, 4, 224, 14, 52, 141, 129, 239, 76, 113, 8, 200, 248, 105, 28, 193, 
		125, 194, 29, 181, 249, 185, 39, 106, 77, 228, 166, 114, 154, 201, 9, 120, 
		101, 47, 138, 5, 33, 15, 225, 36, 18, 240, 130, 69, 53, 147, 218, 142, 
		150, 143, 219, 189, 54, 208, 206, 148, 19, 92, 210, 241, 64, 70, 131, 56, 
		102, 221, 253, 48, 191, 6, 139, 98, 179, 37, 226, 152, 34, 136, 145, 16, 
		126, 110, 72, 195, 163, 182, 30, 66, 58, 107, 40, 84, 250, 133, 61, 186, 
		43, 121, 10, 21, 155, 159, 94, 202, 78, 212, 172, 229, 243, 115, 167, 87, 
		175, 88, 168, 80, 244, 234, 214, 116, 79, 174, 233, 213, 231, 230, 173, 232, 
		44, 215, 117, 122, 235, 22, 11, 245, 89, 203, 95, 176, 156, 169, 81, 160, 
		127, 12, 246, 111, 23, 196, 73, 236, 216, 67, 31, 45, 164, 118, 123, 183, 
		204, 187, 62, 90, 251, 96, 177, 134, 59, 82, 161, 108, 170, 85, 41, 157, 
		151, 178, 135, 144, 97, 190, 220, 252, 188, 149, 207, 205, 55, 63, 91, 209, 
		83, 57, 132, 60, 65, 162, 109, 71, 20, 42, 158, 93, 86, 242, 211, 171, 
		68, 17, 146, 217, 35, 32, 46, 137, 180, 124, 184, 38, 119, 153, 227, 165, 
		103, 74, 237, 222, 197, 49, 254, 24, 13, 99, 140, 128, 192, 247, 112, 7};

	 public final static int[] AlogTable = {
		1, 3, 5, 15, 17, 51, 85, 255, 26, 46, 114, 150, 161, 248, 19, 53, 
		95, 225, 56, 72, 216, 115, 149, 164, 247, 2, 6, 10, 30, 34, 102, 170, 
		229, 52, 92, 228, 55, 89, 235, 38, 106, 190, 217, 112, 144, 171, 230, 49, 
		83, 245, 4, 12, 20, 60, 68, 204, 79, 209, 104, 184, 211, 110, 178, 205, 
		76, 212, 103, 169, 224, 59, 77, 215, 98, 166, 241, 8, 24, 40, 120, 136, 
		131, 158, 185, 208, 107, 189, 220, 127, 129, 152, 179, 206, 73, 219, 118, 154, 
		181, 196, 87, 249, 16, 48, 80, 240, 11, 29, 39, 105, 187, 214, 97, 163, 
		254, 25, 43, 125, 135, 146, 173, 236, 47, 113, 147, 174, 233, 32, 96, 160, 
		251, 22, 58, 78, 210, 109, 183, 194, 93, 231, 50, 86, 250, 21, 63, 65, 
		195, 94, 226, 61, 71, 201, 64, 192, 91, 237, 44, 116, 156, 191, 218, 117, 
		159, 186, 213, 100, 172, 239, 42, 126, 130, 157, 188, 223, 122, 142, 137, 128, 
		155, 182, 193, 88, 232, 35, 101, 175, 234, 37, 111, 177, 200, 67, 197, 84, 
		252, 31, 33, 99, 165, 244, 7, 9, 27, 45, 119, 153, 176, 203, 70, 202, 
		69, 207, 74, 222, 121, 139, 134, 145, 168, 227, 62, 66, 198, 81, 243, 14, 
		18, 54, 90, 238, 41, 123, 141, 140, 143, 138, 133, 148, 167, 242, 13, 23, 
		57, 75, 221, 124, 132, 151, 162, 253, 28, 36, 108, 180, 199, 82, 246, 1};
    
	/*
	 * expandKey() expands the key
	 * expandedKey is a 4x60 matrixx
	 */
	public static void expandKey(int[][] k, int[][] w) {
		for(int j = 0; j < 8; j++)
			for (int i = 0; i < 4; i++)
				w[i][j] = k[i][j];
		
		for (int j = 8; j < 60; j++) {
			if (j % 8 == 0) {
				w[0][j] = w[0][j-8] ^ subBytesReplace(w, 1, j-1) ^ rcon[j/8];
				for (int i = 1; i < 4; i++)
					w[i][j] = w[i][j-8] ^ subBytesReplace(w, (i+1)%4, j-1);
			}
			else if (j % 8 == 4) {
				for (int i = 0; i < 4; i++)
					w[i][j] = w[i][j-8] ^ subBytesReplace(w, i, j-1);
			}
			else {
				for (int i = 0; i < 4; i++)
					w[i][j] = w[i][j-8] ^ w[i][j-1];
			}
		}
		System.out.println("The expanded key is:");

//		String str = "";
//		String currentVal = "";
//		for (int i = 0; i < w.length; i++) {
//			for (int j = 0; j < w[0].length; j++) {
//				currentVal = Integer.toHexString(w[i][j]).toUpperCase();
//				// 06 will be converted to 6, so need to manually add a 0 in front
//				if (currentVal.length() == 1)
//					currentVal = "0" + currentVal; 
//				str += currentVal;
//			}
//		}
//		System.out.println(str);
	}
	
	//--------------------------------------ENCODING-----------------------------------------------
	/*
	 * encodes the inputfile with the given key string
	 * creates an encrypted outputfile (inputFile.enc)
	 */
	public static void encode(File inputFile, String key, File outputFile) throws IOException {
		PrintWriter pw = new PrintWriter(outputFile);
		// 1. expand cipher key
		expandKey(keyMatrix, expandedKey);
		// 2. add round key
		addRoundKey(0);
		// 3. 13 rounds
		for (int i = 1; i < 14; i++) {
			subBytes();
			shiftRows();
			// mixColmn 4 times
			for (int col = 0; col < 4; col++) {
				mixColumn2(col);
			}
			System.out.println("After mixColumns:");
			printState();
			addRoundKey(i);
		}
		// 14. last round has no mixColumn
		subBytes();
		shiftRows();
		addRoundKey(14);
	}
	
	/*
	 * subBytesReplace() replaces the value at the specific r and c for the specified matrix m
	 * r the row position to replace
	 * c the column position to replace
	 */
	public static int subBytesReplace(int[][] m, int r, int c) {
		int val = m[r][c];
        // Convert each int value into Hex form first
        String hex = Integer.toHexString(val);
        // if the hex is 00, or 01, 02, 03...java parses it just to 0, 1, 2, 3..need to manually add a 0 TO FRONT
        // ORDER OF ZEROS MATTER!!
        if (hex.length() == 1)
			hex = "0" + hex;
    	int row = Integer.parseInt(hex.charAt(0) + "",16);
    	int column = Integer.parseInt(hex.charAt(1) + "",16);
    	m[r][c] = sBox[row][column];
		return m[r][c];
	}
	
	/*
	 * subBytes() performs substitution. Replaces all values in state with values from sBox[][]
	 */
	public static void subBytes() {
		for (int row=0; row < state.length; row++) {
		    for (int col=0; col < state[row].length; col++) {
		    	subBytesReplace(state, row, col);
		    }
		}
		// Print state after subBytes()
		System.out.println("After subBytes:");
		printState();
	}
	
	/*
	 * shiftRows() shifts the last three rows to the left. 
	 * row 0 = same
	 * row 1 = shift left 1 byte
	 * row 2 = shifted left 2 bytes
	 * row 3 = shifted left 3 bytes
	 */
	public static void shiftRows() {
		// first row shifted once
		state[1] = rotWord(state[1]);
		// second row shifted twice
		state[2] = rotWord(state[2]);
		state[2] = rotWord(state[2]);
		// third row shifted 3 times
		state[3] = rotWord(state[3]);
		state[3] = rotWord(state[3]);
		state[3] = rotWord(state[3]);
		
		// Print state after shiftRows()
		System.out.println("After shiftRows:");
		printState();
	}
	
	/*
	 * rotWord takes a word (an array) and rotates it one byte to the left so that the first value becomes the last
	 * returns the rotated word
	 * used in shiftRows()
	 */
	public static int[] rotWord(int[] row) {
		int temp = row[0];
		for (int i = 0; i < 3; i++) {
			row[i] = row[i+1];
		}
		// first becomes last
		row[3] = temp; 
		return row;
	}
	
    // In the following two methods, the input c is the column number in
    // your evolving state matrix st (which originally contained 
    // the plaintext input but is being modified).  Notice that the state here is defined as an
    // array of bytes.  If your state is an array of integers, you'll have
    // to make adjustments. 
	// SOURCE: https://www.cs.utexas.edu/~byoung/cs361/mixColumns-cheat-sheet
	public static void mixColumn2(int c) { 
		int a[] = new int[4];
		for (int i = 0; i < 4; i++) { 
			a[i] = state[i][c];
		} 
		state[0][c] = (mul(2, a[0]) ^ a[2] ^ a[3] ^ mul(3, a[1]));
		state[1][c] = (mul(2, a[1]) ^ a[3] ^ a[0] ^ mul(3, a[2]));
		state[2][c] = (mul(2, a[2]) ^ a[0] ^ a[1] ^ mul(3, a[3]));
		state[3][c] = (mul(2, a[3]) ^ a[1] ^ a[2] ^ mul(3, a[0]));
	}  
	
	private static int mul(int a, int b) {
		int inda = (a < 0) ? (a + 256) : a;
		int indb = (b < 0) ? (b + 256) : b;

		if ((a != 0) && (b != 0)) {
			int index = (LogTable[inda] + LogTable[indb]);
			int val = (AlogTable[index % 255]);
			return val;
		} else
			return 0;
	}  
	
	/*
	 * A bit-wise XOR between the state and expanded key
	 * expandedKey has more columns (60) than state (4), so MAKE SURE KEY IS SHIFTED WHEN XOR-ING
	 * SHIFT THE EXPANDEDKEY COLUMNS AT EVERY ROUND!! 
	 */
	public static void addRoundKey(int round) {
		int shift = round * state.length;
		for (int col = 0; col < state.length; col++) {
			for (int row = 0; row < state[0].length; row++) {
				// expanded key doesn't take in state's col number, needs to go all the way to 59!!!
				state[row][col] ^= expandedKey[row][shift];
			}
			shift++;
		} 
		System.out.println("After addRoundKey(" + round + "):");
		printState();
	}
	
	//--------------------------------------DECODING-----------------------------------------------
	/*
	 * decodes the inputfile with the given key
	 * creates a decrypted file (inputFile.dec)
	 */
	public static void decode(File inputFile, String key, File outputFile) throws IOException {
		PrintWriter pw = new PrintWriter(outputFile);
		expandKey(keyMatrix, expandedKey);
		// before first round begins
		addRoundKey(14);
		invShiftRows();
		invSubBytes();
		for (int i = 13; i > 0; i--) {
			addRoundKey(i);
			for (int col = 0; col < 4; col++) {
				invMixColumn2(col);
			}
			System.out.println("After invMixColumns:");
			printState();
//			invShiftRows();
//			invSubBytes();
		}
		addRoundKey(0);
	}

	public static int invSubBytesReplace(int[][] m, int r, int c) {
		int val = m[r][c];
        // Convert each int value into Hex form first
        String hex = Integer.toHexString(val);
        // if the hex is 00, or 01, 02, 03...java parses it just to 0, 1, 2, 3..need to manually add a 0 TO FRONT
        // ORDER OF ZEROS MATTER!!
        if (hex.length() == 1)
			hex = "0" + hex;
    	int row = Integer.parseInt(hex.charAt(0) + "",16);
    	int column = Integer.parseInt(hex.charAt(1) + "",16);
    	m[r][c] = invSBox[row][column];
		return m[r][c];
	}
	
	/*
	 * invSubBytes() performs substitution. Replaces all values in state with values from invSBox[][]
	 */
	public static void invSubBytes() {
		for (int row=0; row < state.length; row++) {
		    for (int col=0; col < state[row].length; col++) {
		    	invSubBytesReplace(state, row, col);
		    }
		}
		// Print state after invSubBytes()
		System.out.println("After invSubBytes:");
		printState();
	}

	/*
	 * invShiftRows() shifts the last three rows to the right. 
	 * row 0 = same
	 * row 1 = shift right 1 byte
	 * row 2 = shifted right 2 bytes
	 * row 3 = shifted right 3 bytes
	 */
	public static void invShiftRows() {
		// first row shifted once
		state[1] = invRotWord(state[1]);
		// second row shifted twice
		state[2] = invRotWord(state[2]);
		state[2] = invRotWord(state[2]);
		// third row shifted 3 times
		state[3] = invRotWord(state[3]);
		state[3] = invRotWord(state[3]);
		state[3] = invRotWord(state[3]);
		// Print state after invShiftRows()
		System.out.println("After invShiftRows:");
		printState();
	}
	
	/*
	 * invRotWord takes a word (an array) and rotates it one byte to the right so that the last value becomes the first
	 * returns the rotated word
	 * used in shiftRows()
	 */
	public static int[] invRotWord(int[] row) {
		int temp = row[3];
		for (int i = 3; i > 0; i--) {
			row[i] = row[i-1];
		}
		// last becomes first
		row[0] = temp; 
		return row;
	}
	
	// SOURCE: https://www.cs.utexas.edu/~byoung/cs361/mixColumns-cheat-sheet
	public static void invMixColumn2(int c) {
		int a[] = new int[4];
		for (int i = 0; i < 4; i++) {
			a[i] = state[i][c];
		}
		state[0][c] = (mul(14, a[0]) ^ mul(11, a[1]) ^ mul(13, a[2]) ^ mul(9, a[3]));
		state[1][c] = (mul(14, a[1]) ^ mul(11, a[2]) ^ mul(13, a[3]) ^ mul(9, a[0]));
		state[2][c] = (mul(14, a[2]) ^ mul(11, a[3]) ^ mul(13, a[0]) ^ mul(9, a[1]));
		state[3][c] = (mul(14, a[3]) ^ mul(11, a[0]) ^ mul(13, a[1]) ^ mul(9, a[2]));
	}
	
	// ------------------------------------------CREATING MATRICES-----------------------------------------
	public static void createStateMatrix(String line) {
		// 00112233(Col1)	44556677(Col2)	8899AABB(Col3)	CCDDEEFF(Col4)
		int row = 0;
		int column = 0;
		for (int i = 0; i < line.length(); i+=2) {
			String hex = line.charAt(i) + "" + line.charAt(i+1);
			// convert hex to int using Integer.parseInt(string, 16)
			state[row][column] = Integer.parseInt(hex, 16);
			// Fill in each column first
			if ((i+2) % 8 == 0) {
				column++;
				row = 0;
			} else {
				row++;
			}
		}
		// Print out state array to console
		System.out.println("The Plaintext is:");
		printMatrix(state);
	}
	
	/*
	 * createkeymatrix() converts keystring into a 4x8 matrix
	 */
	public static void createKeyMatrix(String key) {
		// 0000000000000000000000000000000000000000000000000000000000000000
		int row = 0;
		int col = 0;
		for (int i=0; i < key.length(); i+=2) {
			String hex = key.charAt(i) + "" + key.charAt(i+1);
			keyMatrix[row][col] = Integer.parseInt(hex, 16);
			// Fill in each column first
			if ((i+2) % 8 == 0) {
				col++;
				row = 0;
			} else {
				row++;
			}
		}
		// Print out state array to console
		System.out.println("The CipherKey is:");
		printMatrix(keyMatrix);
	}
	/*
	 * printMatrix prints out all matrixes in correct format
	 */
	public static void printMatrix(int[][] m) {
		for (int i=0; i < m.length; i++) {
		    for (int j=0; j < m[i].length; j++) {
		    	// convert int back to hex using Integer.toHexString(int)
		    	String val = Integer.toHexString(m[i][j]).toUpperCase();
		    	if (val.length() == 1)
					val = "0" + val;
				System.out.print(val + "\t");
		    }
    		System.out.println();
		}
		System.out.println();
	}
	
	/*
	 * printState prints state matrix in one giant string
	 */
	public static void printState() {
		String str = "";
		String currentVal = "";
		for (int i = 0; i < state.length; i++) {
			for (int j = 0; j < state[0].length; j++) {
				currentVal = Integer.toHexString(state[j][i]).toUpperCase();
				// 06 will be converted to 6, so need to manually add a 0 in front
				if (currentVal.length() == 1)
					currentVal = "0" + currentVal; 
				str += currentVal;
			}
		}
		System.out.println(str);
	}
	
	public static void main(String args[]) throws FileNotFoundException {
		// Parse command line args
		// java AES e key plaintext
		File inputFile = new File(args[2]);
		File key = new File(args[1]);
		File outputFile = null;
		boolean encoding = false;
		String keyString = "";
		
		// Parse command line action - Encoding or Decoding
		String action = args[0];
		if (action.equals("e")) {
			encoding = true;
			outputFile = new File(args[2] + ".enc");
		}
		else {
			outputFile = new File(args[2] + ".dec");
		}
		
		Scanner scanInput = new Scanner(inputFile);
		Scanner scanKey = new Scanner(key);
		
		try {
			// get keyString
			while (scanKey.hasNextLine()) {
				keyString += scanKey.nextLine();
			}
			// LOOP OVER EACH LINE IN INPUTFILE. EACH LINE REPRESENTS 128 BITS
			while (scanInput.hasNextLine()) {
				String line = scanInput.nextLine();
				// Fill state array
				createStateMatrix(line);
				createKeyMatrix(keyString);
				// Call encode/decode
				if (encoding) {
					encode(inputFile, keyString, outputFile);
				} else {
					decode(inputFile, keyString, outputFile);
				}
			}
			scanInput.close();
			scanKey.close();
		} catch(IOException e) {
			System.out.println(e.toString() + "occurred when opening file!!");
		}
	}	
}
