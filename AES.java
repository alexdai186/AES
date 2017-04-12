import java.io.*;
import java.lang.*;
import java.util.*;

public class AES {
	private static int[][] state = new int[4][4]; // 128 bit input, in a 4x4 array

	/*
	 * encodes the inputfile with the given key
	 * creates an encrypted outputfile (inputFile.enc)
	 */
	public static void encode(File inputFile, File key, File outputFile) throws IOException {
		PrintWriter pw = new PrintWriter(outputFile);
		expandKey();
		// before first round begins
		addRoundKey(0);
		for (int i = 1; i < 14; i++) {
			subBytes();
			shiftRows();
			mixColumns();
			addRoundKey(i);
		}
		subBytes();
		shiftRows();
		addRoundKey(14);
	}
	public static void subBytes() {

	}
	public static void shiftRows() {

	}
	public static void mixColumns() {
	
	}
	// A bit-wise XOR between the state and expanded key
	public static void addRoundKey(int i) {
	
	}
	public static void expandKey() {

	}
	/*
	 * decodes the inputfile with the given key
	 * creates a decrypted file (inputFile.dec)
	 */
	public static void decode(File inputFile, File key, File outputFile) throws IOException {
		PrintWriter pw = new PrintWriter(outputFile);
		expandKey();
		// before first round begins
		addRoundKey(14);
		invShiftRows();
		invSubBytes();
		for (int i = 13; i > 0; i--) {
			addRoundKey(i);
			invMixColumns();
			invShiftRows();
			invSubBytes();
		}
		addRoundKey(0);
	}
	public static void invSubBytes() {

	}
	public static void invShiftRows() {

	}
	public static void invMixColumns() {
	
	}
	public static void createStateArray(String line) {
		// 0A935D11496532BC1004865ABDCA4295
		int row = 0;
		int column = 0;
		for (int i = 0; i < line.length(); i+=2) {
			// convert hex to int using Integer.parseInt(string, 16)
			// convert int back to hex using Integer.toHexString(int)
			String hex = line.charAt(i) + "" + line.charAt(i+1);
			state[row][column] = Integer.parseInt(hex, 16);
			System.out.println(state[row][column] + "at row "+ row + " column "+ column);
			if ((i+2) % 8 == 0) {
				row++;
				column = 0;
			} else {
				column++;
			}
		}
	}
	public static void main(String args[]) throws FileNotFoundException {
		// Parse command line args
		// java AES e key plaintext
		File inputFile = new File(args[2]);
		File key = new File(args[1]);
		File outputFile = null;
		boolean encoding = false;
		
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
		try {
			// LOOP OVER EACH LINE IN INPUTFILE. EACH LINE REPRESENTS 128 BITS
			while (scanInput.hasNextLine()) {
				String line = scanInput.nextLine();
				// Fill state array
				createStateArray(line);
				
				// Call encode/decode
				if (encoding) {
					encode(inputFile, key, outputFile);
				} else {
					decode(inputFile, key, outputFile);
				}
			}
			scanInput.close();
		} catch(IOException e) {
			System.out.println(e.toString() + "occurred when opening file!!");
		}
	}	
}
