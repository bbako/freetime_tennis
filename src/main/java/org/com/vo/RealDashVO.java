package org.com.vo;

public class RealDashVO {
	
	String stt_date;
	Integer success;
	
	public String getStt_date() {
		return stt_date;
	}
	public void setStt_date(String stt_date) {
		this.stt_date = stt_date;
	}
	public Integer getSuccess() {
		return success;
	}
	public void setSuccess(Integer success) {
		this.success = success;
	}
	
	@Override
	public String toString() {
		return "RealDashVO [stt_date=" + stt_date + ", success=" + success + "]";
	}
	
}
