package org.com.util;

public class RecognitionData {

	public String r_file_nm = "";
	public double result_rate1 = 0;
	public double result_rate2 = 0;
	public int result_h = 0;
	public int result_d = 0;
	public int result_s = 0;
	public int result_i = 0;
	public int result_n = 0;

	public RecognitionData(String value) {
		byte[] tmp = value.getBytes();
		int next = 0;
		int size = tmp.length;
		for (int i = 0; i < size; ++i) {
			if (tmp[i] == ' ' || tmp[i] == '[') {
				next = i;
			} else if (tmp[i] == ':') {
				this.r_file_nm = value.substring(next, i);
				next = i;
			} else if (tmp[i] == '(') {
				this.result_rate1 = getDouble(value.substring(next, i - 1));
				next = i + 1;
			} else if (tmp[i] == ')') {
				this.result_rate2 = getDouble(value.substring(next, i - 1));
				next = i + 1;
			} else if (tmp[i] == 'H' && tmp[i + 1] == '=') {
				next = i + 2;
				for (int j = next; j < size; ++j) {
					if (tmp[j] == ',') {
						this.result_h = getInt(value.substring(next, j));
						i = j + 1;
						break;
					}
				}
			} else if (tmp[i] == 'D' && tmp[i + 1] == '=') {
				next = i + 2;
				for (int j = next; j < size; ++j) {
					if (tmp[j] == ',') {
						this.result_d = getInt(value.substring(next, j));
						i = j + 1;
						break;
					}
				}
			} else if (tmp[i] == 'S' && tmp[i + 1] == '=') {
				next = i + 2;
				for (int j = next; j < size; ++j) {
					if (tmp[j] == ',') {
						this.result_d = getInt(value.substring(next, j));
						i = j + 1;
						break;
					}
				}
			} else if (tmp[i] == 'I' && tmp[i + 1] == '=') {
				next = i + 2;
				for (int j = next; j < size; ++j) {
					if (tmp[j] == ',') {
						this.result_d = getInt(value.substring(next, j));
						i = j + 1;
						break;
					}
				}
			} else if (tmp[i] == 'N' && tmp[i + 1] == '=') {
				next = i + 2;
				for (int j = next; j < size; ++j) {
					if (tmp[j] == ',') {
						this.result_d = getInt(value.substring(next, j));
						i = j + 1;
						break;
					}
				}
			}
		}
	}

	public int getInt(String value) {

		try {
			return Integer.valueOf(value);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return 0;
	}

	public double getDouble(String value) {

		try {
			return Double.valueOf(value);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return 0;
	}

	public String getR_file_nm() {
		return r_file_nm;
	}

	public void setR_file_nm(String r_file_nm) {
		this.r_file_nm = r_file_nm;
	}

	public double getResult_rate1() {
		return result_rate1;
	}

	public void setResult_rate1(double result_rate1) {
		this.result_rate1 = result_rate1;
	}

	public double getResult_rate2() {
		return result_rate2;
	}

	public void setResult_rate2(double result_rate2) {
		this.result_rate2 = result_rate2;
	}

	public int getResult_h() {
		return result_h;
	}

	public void setResult_h(int result_h) {
		this.result_h = result_h;
	}

	public int getResult_d() {
		return result_d;
	}

	public void setResult_d(int result_d) {
		this.result_d = result_d;
	}

	public int getResult_s() {
		return result_s;
	}

	public void setResult_s(int result_s) {
		this.result_s = result_s;
	}

	public int getResult_i() {
		return result_i;
	}

	public void setResult_i(int result_i) {
		this.result_i = result_i;
	}

	public int getResult_n() {
		return result_n;
	}

	public void setResult_n(int result_n) {
		this.result_n = result_n;
	}

}
