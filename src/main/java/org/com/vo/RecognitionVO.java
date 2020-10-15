package org.com.vo;

public class RecognitionVO {

	String r_file_nm;
	String r_file_path;
	String r_start_tm;
	String r_end_tm;
	Integer r_duration;
	String r_io_gbn;
	String r_user_id;
	String r_group_id;
	String r_team_id;
	String r_user_nm;
	String r_stt_date;
	Integer result_rate;
	
	String stt_text;
	String answer_text;
	Integer result_rate1;
	Integer result_rate2;
	Integer result_h;
	Integer result_d;
	Integer result_s;
	Integer result_i;
	Integer result_n;
	String result_date;
	String status;
	public String getR_file_nm() {
		return r_file_nm;
	}
	public void setR_file_nm(String r_file_nm) {
		this.r_file_nm = r_file_nm;
	}
	public String getR_file_path() {
		return r_file_path;
	}
	public void setR_file_path(String r_file_path) {
		this.r_file_path = r_file_path;
	}
	public String getR_start_tm() {
		return r_start_tm;
	}
	public void setR_start_tm(String r_start_tm) {
		this.r_start_tm = r_start_tm;
	}
	public String getR_end_tm() {
		return r_end_tm;
	}
	public void setR_end_tm(String r_end_tm) {
		this.r_end_tm = r_end_tm;
	}
	public Integer getR_duration() {
		return r_duration;
	}
	public void setR_duration(Integer r_duration) {
		this.r_duration = r_duration;
	}
	public String getR_io_gbn() {
		return r_io_gbn;
	}
	public void setR_io_gbn(String r_io_gbn) {
		this.r_io_gbn = r_io_gbn;
	}
	public String getR_user_id() {
		return r_user_id;
	}
	public void setR_user_id(String r_user_id) {
		this.r_user_id = r_user_id;
	}
	public String getR_group_id() {
		return r_group_id;
	}
	public void setR_group_id(String r_group_id) {
		this.r_group_id = r_group_id;
	}
	public String getR_team_id() {
		return r_team_id;
	}
	public void setR_team_id(String r_team_id) {
		this.r_team_id = r_team_id;
	}
	public String getR_user_nm() {
		return r_user_nm;
	}
	public void setR_user_nm(String r_user_nm) {
		this.r_user_nm = r_user_nm;
	}
	public String getR_stt_date() {
		return r_stt_date;
	}
	public void setR_stt_date(String r_stt_date) {
		this.r_stt_date = r_stt_date;
	}
	public Integer getResult_rate() {
		return result_rate;
	}
	public void setResult_rate(Integer result_rate) {
		this.result_rate = result_rate;
	}
	public String getStt_text() {
		return stt_text;
	}
	public void setStt_text(String stt_text) {
		this.stt_text = stt_text;
	}
	public String getAnswer_text() {
		return answer_text;
	}
	public void setAnswer_text(String answer_text) {
		this.answer_text = answer_text;
	}
	public Integer getResult_rate1() {
		return result_rate1;
	}
	public void setResult_rate1(Integer result_rate1) {
		this.result_rate1 = result_rate1;
	}
	public Integer getResult_rate2() {
		return result_rate2;
	}
	public void setResult_rate2(Integer result_rate2) {
		this.result_rate2 = result_rate2;
	}
	public Integer getResult_h() {
		return result_h;
	}
	public void setResult_h(Integer result_h) {
		this.result_h = result_h;
	}
	public Integer getResult_d() {
		return result_d;
	}
	public void setResult_d(Integer result_d) {
		this.result_d = result_d;
	}
	public Integer getResult_s() {
		return result_s;
	}
	public void setResult_s(Integer result_s) {
		this.result_s = result_s;
	}
	public Integer getResult_i() {
		return result_i;
	}
	public void setResult_i(Integer result_i) {
		this.result_i = result_i;
	}
	public Integer getResult_n() {
		return result_n;
	}
	public void setResult_n(Integer result_n) {
		this.result_n = result_n;
	}
	public String getResult_date() {
		return result_date;
	}
	public void setResult_date(String result_date) {
		this.result_date = result_date;
	}
	public String getStatus() {
		return status;
	}
	public void setStatus(String status) {
		this.status = status;
	}
	@Override
	public String toString() {
		return "RecognitionVO [r_file_nm=" + r_file_nm + ", r_file_path=" + r_file_path + ", r_start_tm=" + r_start_tm
				+ ", r_end_tm=" + r_end_tm + ", r_duration=" + r_duration + ", r_io_gbn=" + r_io_gbn + ", r_user_id="
				+ r_user_id + ", r_group_id=" + r_group_id + ", r_team_id=" + r_team_id + ", r_user_nm=" + r_user_nm
				+ ", r_stt_date=" + r_stt_date + ", result_rate=" + result_rate + ", stt_text=" + stt_text
				+ ", answer_text=" + answer_text + ", result_rate1=" + result_rate1 + ", result_rate2=" + result_rate2
				+ ", result_h=" + result_h + ", result_d=" + result_d + ", result_s=" + result_s + ", result_i="
				+ result_i + ", result_n=" + result_n + ", result_date=" + result_date + ", status=" + status + "]";
	}
}
