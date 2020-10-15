package org.com.controller;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.ibatis.session.SqlSession;
import org.com.vo.UserVO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.google.gson.Gson;

@Controller
public class CSUIController extends BaseController {

	private static final Logger logger = LoggerFactory.getLogger(CSUIController.class);
	
	@Value("#{constant['wss.url']}")
	private String wssUrl;
	
	@Autowired
	private SqlSession sqlMapClientTemplate;
	
	@RequestMapping(value = "/csuiUser.do", method = RequestMethod.GET)
	public String csuiUser(HttpServletRequest request, HttpServletResponse response, @RequestParam HashMap<String, String> paramMap, Model model) throws Exception {
		
		UserVO user = sqlMapClientTemplate.selectOne("MainMap.getWFMSInfo", paramMap);
		
		model.addAttribute("wssUrl", wssUrl);
		model.addAttribute("user_id", paramMap.get("user_id"));
		model.addAttribute("user_info", user);
		
		return "csuiUser";
	}
	
	@RequestMapping(value = "/csuiManager.do", method = RequestMethod.POST)
	public String csuiManager(HttpServletRequest request, HttpServletResponse response, @RequestParam HashMap<String, String> paramMap, Model model) throws Exception {
		
		model.addAttribute("user_id", paramMap.get("user_id"));

		UserVO user = sqlMapClientTemplate.selectOne("MainMap.getWFMSInfo", paramMap);
		List<UserVO> u_list = sqlMapClientTemplate.selectList("MainMap.getUser", paramMap);
		String u_list_j = new Gson().toJson(u_list);
		
		model.addAttribute("wssUrl", wssUrl);
		model.addAttribute("list", user);
		model.addAttribute("u_list", u_list_j);
		model.addAttribute("user_duty_cd", user.getUserdutycd());
		
		logger.info(user.toString());
		logger.info(u_list.toString());
		
		return "csuiManager";
	}
	@RequestMapping(value = "/getWFMSInfo.do", method = RequestMethod.POST)
	public @ResponseBody UserVO getWFMSInfo(@RequestParam Map paramMap, Model model) throws Exception {
		
		UserVO user = sqlMapClientTemplate.selectOne("MainMap.getWFMSInfo", paramMap);
		return user;
	}
	
	@RequestMapping(value = "/getUserCnt.do", method = RequestMethod.POST)
	public @ResponseBody List<UserVO> getUserCnt(@RequestParam Map paramMap, Model model) throws Exception {
		List userCnt = select("MainMap.getUserCnt", paramMap);
		return userCnt;
	}

}
