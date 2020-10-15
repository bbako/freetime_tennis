package org.com.vo;

public class UserVO {
	
	String userid;
	String username;
	String orgid;
	String orgnm;
	String usertypecd;
	String usertypecdnm;
	String userdutycd;
	String userdutycdnm;
	String stt_use_yn;
	Integer team_cnt;
	Integer stt_use_cnt;
	Integer call_status;
	
	public String getUserid() {
		return userid;
	}
	public void setUserid(String userid) {
		this.userid = userid;
	}
	public String getUsername() {
		return username;
	}
	public void setUsername(String username) {
		this.username = username;
	}
	public String getOrgid() {
		return orgid;
	}
	public void setOrgid(String orgid) {
		this.orgid = orgid;
	}
	public String getOrgnm() {
		return orgnm;
	}
	public void setOrgnm(String orgnm) {
		this.orgnm = orgnm;
	}
	public String getUsertypecd() {
		return usertypecd;
	}
	public void setUsertypecd(String usertypecd) {
		this.usertypecd = usertypecd;
	}
	public String getUsertypecdnm() {
		return usertypecdnm;
	}
	public void setUsertypecdnm(String usertypecdnm) {
		this.usertypecdnm = usertypecdnm;
	}
	public String getUserdutycd() {
		return userdutycd;
	}
	public void setUserdutycd(String userdutycd) {
		this.userdutycd = userdutycd;
	}
	public String getUserdutycdnm() {
		return userdutycdnm;
	}
	public void setUserdutycdnm(String userdutycdnm) {
		this.userdutycdnm = userdutycdnm;
	}
	public String getStt_use_yn() {
		return stt_use_yn;
	}
	public void setStt_use_yn(String stt_use_yn) {
		this.stt_use_yn = stt_use_yn;
	}
	public Integer getTeam_cnt() {
		return team_cnt;
	}
	public void setTeam_cnt(Integer team_cnt) {
		this.team_cnt = team_cnt;
	}
	public Integer getStt_use_cnt() {
		return stt_use_cnt;
	}
	public void setStt_use_cnt(Integer stt_use_cnt) {
		this.stt_use_cnt = stt_use_cnt;
	}
	public Integer getCall_status() {
		return call_status;
	}
	public void setCall_status(Integer call_status) {
		this.call_status = call_status;
	}
	
	@Override
	public String toString() {
		return "UserVO [userid=" + userid + ", username=" + username + ", orgid=" + orgid + ", orgnm=" + orgnm
				+ ", usertypecd=" + usertypecd + ", usertypecdnm=" + usertypecdnm + ", userdutycd=" + userdutycd
				+ ", userdutycdnm=" + userdutycdnm + ", stt_use_yn=" + stt_use_yn + ", team_cnt=" + team_cnt
				+ ", stt_use_cnt=" + stt_use_cnt + ", call_status=" + call_status + "]";
	}
	
}
	

