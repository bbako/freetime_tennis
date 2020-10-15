package org.com.util;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;

public class RecognitionMain {
	
	public static ArrayList<RecognitionData> main(String sttTextFile, String answerTextFile) {
		System.out.println("RecognitionMain START"); 
		ArrayList<RecognitionData> result = new ArrayList<RecognitionData>();

		if (sttTextFile != null && sttTextFile.length() > 0 && answerTextFile != null && answerTextFile.length() > 0) {
		try{
		Runtime runtime = Runtime.getRuntime();
		String[] params = {"/opt/gosh2/bin/util/compute-results.sh", sttTextFile, answerTextFile};
		Process process = runtime.exec(params);
		process.waitFor(); 
		InputStream is = process.getInputStream();
		InputStreamReader isr = new InputStreamReader(is); 
		BufferedReader br = new BufferedReader(isr);

		String value = null;

		value = br.readLine(); 
		value = br.readLine(); 
		value = br.readLine();

		while ((value = br.readLine()) != null) {
			System.out.println(value); 
			if (value.contains ("Overall Results") == true) {	
				break; } else {
		result.add(new RecognitionData(value));}}
		} catch (Exception e) {
		e.printStackTrace();}}
		System.out.println("RecognitionMain END");
		return result;
	}

}
