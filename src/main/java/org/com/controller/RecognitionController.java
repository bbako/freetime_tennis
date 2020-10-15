package org.com.controller;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.ibatis.session.SqlSession;
import org.com.util.RecognitionData;
import org.com.util.RecognitionMain;
import org.com.vo.RecognitionVO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class RecognitionController extends BaseController {

	private static final Logger logger = LoggerFactory.getLogger(RecognitionController.class);

	@Autowired
	private SqlSession sqlMapClientTemplate;

	@RequestMapping(value = "/recognition.do", method = RequestMethod.GET)
	public String recognition() throws Exception {

		return "recognition";
	}

	@RequestMapping(value = "/getRecognitionList.do", method = RequestMethod.POST)
	public @ResponseBody List<RecognitionVO> getRecognitionList(@RequestParam HashMap<String, String> paramMap) throws Exception {
		logger.info("getRecognitionList.do");
		List<RecognitionVO> recognitionList = sqlMapClientTemplate.selectList("RecognitionMap.getRecognitionList" , paramMap);
		return recognitionList;
	}

	@RequestMapping(value = "/changeStatus.do", method = RequestMethod.POST)
	public void changeStatus(@RequestParam HashMap<String, String> paramMap) throws Exception {
		logger.info("changeStatus.do");
		String status = paramMap.get("status").toString();

		if (status.equals("1")) {

			// get wav
			String r_file_path = getWav(paramMap.get("r_file_nm").toString());
			paramMap.put("r_file_path", r_file_path);

			// insert mst info
			sqlMapClientTemplate.insert("RecognitionMap.insertRedMstInfoForRecognition", paramMap);

			// insert recognition
			sqlMapClientTemplate.insert("RecognitionMap.insertRecognitionInit", paramMap);

		} else if (status.equals("2")) {

			// delete recognition
			sqlMapClientTemplate.delete("RecognitionMap.deleteRecognitionInit", paramMap);

		} else {

		}

	}

	@RequestMapping(value = "/getRecognitionStt.do", method = RequestMethod.POST)
	public @ResponseBody RecognitionVO getRecognitionStt(@RequestParam HashMap<String, String> paramMap)
			throws Exception {
		logger.info("getRecognitionStt.do");
		RecognitionVO recognitionStt = sqlMapClientTemplate.selectOne("RecognitionMap.getRecognitionStt", paramMap);
		return recognitionStt;
	}

	@RequestMapping(value = "/saveAnswerTextTemp.do", method = RequestMethod.POST)
	public @ResponseBody String saveAnswerTextTemp(@RequestParam HashMap<String, String> paramMap) throws Exception {
		logger.info("saveAnswerTextTemp.do");
		logger.info(paramMap.toString());
		sqlMapClientTemplate.update("RecognitionMap.saveAnswerTextTemp", paramMap);
		
		return "success";

	}

	@RequestMapping(value = "/recognitionEvaluate.do", method = RequestMethod.POST)
	public @ResponseBody String recognitionEvaluate(@RequestParam HashMap<String, String> paramMap) throws Exception {
		logger.info("saveAnswerTextTemp.do");
		String r_file_nm = paramMap.get("r_file_nm").toString();
		String stt_text = paramMap.get("sttText").toString();
		String stt_text_line = r_file_nm + ".wav.stt\t" + stt_text.replaceAll("\n", " ");
		String answer_text = paramMap.get("answerText").toString();
		String answer_text_line = r_file_nm + ".wav\t" + answer_text.replaceAll("\n", "");

		Map map = new HashMap();
		map.put("r_file_nm", r_file_nm);
		map.put("answer_text", answer_text);
		
		// make txt files on server (r_file_nm_stt.txt, r_file_nm_ans.txt)
		String yyyyMMdd = new SimpleDateFormat("yyyyMMdd").format(new Date());

		String desPathR = "/sttnas/stt_data/result";
		File destr = new File(desPathR);
		if (destr.exists() == false && destr.isDirectory() == false) {
			destr.mkdir();
		}

		String desPath = "/sttnas/stt_data/result/" + yyyyMMdd;
		File dest = new File(desPath);
		if (dest.exists() == false && dest.isDirectory() == false) {
			dest.mkdir();
		}
		dest.setExecutable(true, false);
		dest.setReadable(true, false);
		dest.setWritable(true, false);
		OutputStream op = new FileOutputStream(desPath + "/" + r_file_nm + "_stt.txt");
		byte[] sttBy = stt_text_line.getBytes();
		op.write(sttBy);
		
		OutputStream op2 = new FileOutputStream(desPath + "/" + r_file_nm + "_ans.txt"); 
		byte[] ansBy = answer_text_line.getBytes();
		 op2.write(ansBy);
		 
		RecognitionMain recog_main = new RecognitionMain();
		ArrayList<RecognitionData> recogn_result = recog_main.main(desPath + "/"+ r_file_nm + "_ans.txt", desPath + "/" + r_file_nm + "_stt.txt");
		
		//update recognition t result
		map.put("result_rate1", recogn_result.get(0).result_rate1);
		map.put("result_rate2", recogn_result.get(0).result_rate2);
		map.put("result_h", recogn_result.get(0).result_h);
		map.put("result_d", recogn_result.get(0).result_d);
		map.put("result_s", recogn_result.get(0).result_s);
		map.put("result_i", recogn_result.get(0).result_i);
		map.put("result_n", recogn_result.get(0).result_n);
		
		sqlMapClientTemplate.update("RecognitionMap.saveRecognitionResult", map);

		return "success";
	}

	public String getWav(String r_file_nm) {
		String yyyyMMdd = new SimpleDateFormat("yyyyMMdd").format(new Date());
		String srcPath = "/sttnas/stt_data/result";
		String desPath = "/sttnas/stt_data/result/" + yyyyMMdd;
		String url = "WorkCode=0002&FileNm=" + r_file_nm + "&dstPath=";

		Socket clientSocket = null;
		OutputStream os = null;
		InputStream is = null;

		File dest = new File(desPath);
		if (dest.exists() == false && dest.isDirectory() == false) {
			dest.mkdir();
		}
		dest.setExecutable(true, false);
		dest.setReadable(true, false);
		dest.setWritable(true, false);

		try {
			clientSocket = new Socket();
			clientSocket.connect(new InetSocketAddress("130.1.56.81", 2000), 5080);
			os = clientSocket.getOutputStream();
			is = clientSocket.getInputStream();
			os.write(url.getBytes());
			os.flush();

			int resultSize = 0;
			byte[] msgByte = new byte[1024];
			String readData = "";

			do {
				resultSize = is.read(msgByte);
				readData += new String(msgByte);
			} while (resultSize >= 1024);

			System.out.println("readData : " + readData);

			if (readData.indexOf("200") != -1 && readData.indexOf("SUCCESS") != -1
					&& new File(srcPath + "/" + r_file_nm + ".wav").exists() == true) {
				Files.move(Paths.get(srcPath + "/" + r_file_nm + ".wav"), Paths.get(desPath + "/" + r_file_nm));
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				if (os != null) {
					os.close();
					os = null;
				}
			} catch (Exception e) {
				e.printStackTrace();
			}

			try {
				if (is != null) {
					is.close();
					is = null;
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		return desPath;
	}
}
