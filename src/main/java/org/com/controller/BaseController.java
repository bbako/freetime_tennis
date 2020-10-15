package org.com.controller;

import java.util.List;

import org.apache.ibatis.session.SqlSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

public class BaseController {

	private static final Logger logger = LoggerFactory.getLogger(BaseController.class);
	
	@Autowired
	private SqlSession sqlMapClientTemplate;
	
	public List select(String id, Object param) {
		return sqlMapClientTemplate.selectList(id, param);
	}

	public Object insert(String id, Object param) {
		return sqlMapClientTemplate.insert(id, param);
	}

	public int update(String id, Object param) {
		return sqlMapClientTemplate.update(id, param);
	}

	public int delete(String id, Object param) {
		return sqlMapClientTemplate.delete(id, param);
	}

	public void log(String s) {
		if (logger.isDebugEnabled()) {
			logger.debug(s);
		}

	}

}
