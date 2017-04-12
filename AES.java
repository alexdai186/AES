import java.io.*;
import java.lang.*;
import java.util.*;

public class AES {
	private static File inputFile = null;
	private static File key = null;
	private static File outputFile = null;
	
	public static void encode() throws IOException {
		PrintWriter pw = new PrintWriter(outputFile);
		expandKey(key);
		// before first round begins
		addRoundKey(0);
		for (int i = 0; i < 14; i++) {
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
	public static void expandKey(File key) {

	}
	public static void decode() throws IOException {
		PrintWriter pw = new PrintWriter(outputFile);
		expandKey(key);
		// before first round begins
		addRoundKey(14);
		invShiftRows();
		invSubBytes();
		for (int i = 13; i >= 1; i--) {
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
	public static void main(String args[]) {
		// Parse command line args
		// java AES e key plaintext
		inputFile = new File(args[2]);
		key = new File(args[1]);
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

		try {
			if (encoding) {
				encode();
			} else {
				decode();
			}
		} catch(IOException e) {
			System.out.println(e.toString() + "occurred when opening file!!");
		}
	}	
}
