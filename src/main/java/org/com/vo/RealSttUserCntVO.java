package org.com.vo;

public class RealSttUserCntVO {
	
	Integer stt_user;
	Integer calling_user;
	
	public Integer getStt_user() {
		return stt_user;
	}
	public void setStt_user(Integer stt_user) {
		this.stt_user = stt_user;
	}
	public Integer getCalling_user() {
		return calling_user;
	}
	public void setCalling_user(Integer calling_user) {
		this.calling_user = calling_user;
	}
	
	@Override
	public String toString() {
		return "RealSttUserCntVO [stt_user=" + stt_user + ", calling_user=" + calling_user + "]";
	}
}
