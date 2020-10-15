package org.com.controller;

import java.util.List;

import org.apache.ibatis.session.SqlSession;
import org.com.vo.RealDashVO;
import org.com.vo.RealSttUserCntVO;
import org.com.vo.SemiRealDashVO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class DashBoardController extends BaseController {

	private static final Logger logger = LoggerFactory.getLogger(DashBoardController.class);
	
	@Autowired
	private SqlSession sqlMapClientTemplate;
	
	@RequestMapping(value = "/dashBoard.do", method = RequestMethod.GET)
	public String dashBoard() throws Exception {
		return "dashBoard";
	}
	
	@RequestMapping(value = "/getRealdata.do", method = RequestMethod.POST)
	public @ResponseBody List<RealDashVO> getWFMSInfo() throws Exception {
		
		List<RealDashVO> realData = sqlMapClientTemplate.selectList("DashBoardMap.getRealdata");
		return realData;
	}
	
	@RequestMapping(value = "/getSemiRealdata.do", method = RequestMethod.POST)
	public @ResponseBody List<SemiRealDashVO> getSemiRealdata() throws Exception {
		
		List<SemiRealDashVO> SemiRealDash = sqlMapClientTemplate.selectList("DashBoardMap.getSemiRealdata");
		return SemiRealDash;
	}
	
	@RequestMapping(value = "/getRealSttUserCnt.do", method = RequestMethod.POST)
	public @ResponseBody List<RealSttUserCntVO> getRealSttUserCnt() throws Exception {
		
		List<RealSttUserCntVO> realSttUserCnt = sqlMapClientTemplate.selectList("DashBoardMap.getRealSttUserCnt");
		return realSttUserCnt;
	}
	

}
