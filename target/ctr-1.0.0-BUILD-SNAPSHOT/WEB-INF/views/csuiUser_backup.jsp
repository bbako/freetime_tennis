<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="">
<meta name="author" content="">
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">

<script type="text/javascript" src="/resources/js/jquery/jquery-3.4.1.min.js"></script>
<script type="text/javascript" src="/resources/js/socket/sockjs.min.js"></script>
<script type="text/javascript" src="/resources/js/bootstrap/js/bootstrap.min.js"></script>


<link rel="stylesheet" media="(min-width: 651px) and (max-width: 5000px)" href="/resources/css/style_full_callmemV04arrange.css">
<link rel="stylesheet" media="(min-width: 0px) and (max-width: 650px)" href="/resources/css/style_small_callmemV04arrange.css">
<link rel="stylesheet" href="/resources/css/chatV04arrange.css">
<link rel="stylesheet" href="/resources/css/tableV04arrange.css">
<link rel="stylesheet" href="/resources/css/radiobtnV04arrange.css">

<link rel="stylesheet" href="/resources/js/bootstrap/css/bootstrap.min.css">

<title>BC Card</title>

<script type="text/javascript">
	
	var apClassCd1, apclassCd2, apclassCd3;

	$(document).ready(function() {
		// setInterval("sendPing()", 20000); 
		setInterval("startTime()", 1000); 
		// connectWebSocket();
		getWFMSInfo();
	
		$("#ap_memo").bind("change", function(){
			var apMemoText = $("#ap_memo").val(); 
			if(apMemoText.length > 500) {
				alert(" 500자 이하 ");
				$("#ap_memo").val("");
				$("#ap memo").focus();
			}
		});
	});
	
	function startTime() {
		var today = new Date(); 
		var year = today.getFullYear(); 
		var month = checkTime (today.getMonth() + 1); 
		var date = checkTime(today.getDate()); 
		var day = today.getDay(); 
		var hour = checkTime (today.getHours()); 
		var min = checkTime(today.getMinutes()); 
		var sec = checkTime (today.getSeconds()); 
		var week = new Array('일','월','화','수','목','금','토'); 
		var dayLabel = week[day]; 
		$("#c_time").html(
			"<span>" +
			year + "-" + month + "-" + date + "(" + dayLabel + ")" + hour + ":" + min + ":" + sec +
			"</span>"
			);
		// var t = setTimeout(startTime, 500);
	};

	function div_Onoff (v, id) { 
		if(v == "4") {
			document.getElementById("con").style.visibility = "visible"; 
		} else {
			document.getElementById("con").style.visibility = "hidden";
		}
	}

	function getWFMSInfo() {
		
		console.log("getWFMSInfo");
		console.log("${user_id}");
		
		$.ajax({
			type : 'POST', 
			url : '/getWFMSInfo.do',
			data : {
				user_id : "${user_id}"
			},
			error : function(XMLHttpRequest, textStatus, errorThrown) {
				console.log("error");
				console.log(textStatus);
			},
			success : function(data) {
				$("#uGroup").html("|" + data[0].orgnm); 
				$("#uName").html("|" + data[0].username); 
				$("#tempGroupNm").val(data[0].orgnm);
			}
		})
	};
	
	function checkTime(i) {
		if(i<10){
			i = "0" + i;
		}
		return i;
	}
	
	function getchat() { 
		exSocket.send(JSON.stringify({
			type : "user id", 
			r_csr_id : "${user_id}", 
			level : "1"
		}));
	}

	var exSocket = null;

	function sendPing() { 
		if (exSocket != null) { 
			exSocket.send(ISON.stringify({
				type : "ping",
				r_csr_id : "${user_id}"
			})); 
		}
	}
	
	var call_key = "";
	var isEnd = false;

	function connectWebSocket() { 
		if(exSocket == null) {
			
			exSocket = new WebSocket("${wssUrl}"); 
			
			exSocket.onopen = function(event) {
				getchat(); 
			};
			
			exSocket.onclose = function(event) {
				exSocket = null;
				connectWebSocket(); 
			}; 
			
			exSocket.onmessage = function(event) {
				var jsonData = JSON.parse(event.data);
				console.log(jsonData);

				if (jsonData.type == "call_start") {
					
					isEnd = false; 
					
					if(call_key != jsonData["r_real_call_key"]){
						$(".chatlog").empty();
					}
					
					call_key = jsonData["r_real_call_key"]; 
					$("#callNum").html(jsonData.r_cid);
					
					//start 
					$(".rule").hide(); 
					$(".bc_box-in-type").attr("style", "border-radius:10px 10px Opx Opx !important");
					$(".bc_container").animate({scrollTop:0}, 400);
					$("#ap_class_cd1").val(); 
					$("#ap class cd2").val();
					$("#ap_class_cd3").val();
					$("#ap_memo").val(''); 
					$("#srchArea").hide();
					$(".js-search").val('');
				} else if (jsonData.type == "call_end") { 
					if(isEnd == false) {
						isEnd = true; 
					$(".rule").show(); 
					$(".bc_box-in-type").attr("style", "border-radius:10px 10px 10px 10px !important");
					$(".bc_container").animate({scrollTop:$(".bc_container").height()}, 400); 
					// analyse(jsonData["r_real_call_key"]);
					}
				} else if (jsonData.type == "call_text") { 
					for(var i = 0; i < jsonData.data.length; ++i) {
						// var rtobj = getSelctor(jsonData.data[i]);

						if(!rtObj) {
							if (jsonData.data[i].r_mode_cd == '1') {
								$(".chatlog").append( 
														"<div id='" + jsonData.data[i].r_start_tm_order + "' class='chatlog_mine'>" + 
														"<span class='time'>" +
														jsonData.data[i].r_start_tm + "<br>" + jsonData.data[i].r_end_tm + 
														"</span>" + 
														"<p>" +
														jsonData.data[i].r_stt_text + 
														"</p>" + 
														"</div>"
													);
							} else { 
								$(".chatlog").append( 
														"<div id='" + jsonData.data[i].r_start_tm_order + "' class='chatlog_receive'>" + 
														"<h5>고객</h5>" +
														"<p>" +
														jsonData.data[i].r_stt_text +
														"</p>" + 
														"<span class='time'>" +
														jsonData.data[i].r_start_tm + "<br>" + jsonData.data[i].r_end_tm + 
														"</span>" + 
														"</div>"
													);
							}
						}
					}
					$("#chatlog").scrollTop($("#chatlog")[0].scrollHeight);
				}
			};
		}
	}

//	function getSelctor(obj) {
//		var time = obj.r_start_tm_order;
//	 	var flag = false;
//		$("#chatlog div").each(function() {
//			var preTime = $(this).attr('id');
//			if(Number(preTime) > Number(time)) { 
//				if(!flag) { 
//					if(obj.r_mode_cd == '1') {
//	 					$(this).before(
//										"<div id='" + obj.r_start_tm + "' class='chatlog_mine'>" + 
//										"<span class='time'>" +
//										obj.r_start_tm + "<br>" + obj.r_end_tm + 
//										"</span>" + 
//										"<p>" +
//										obj.r_stt_text + 
//										"</p>" + 
//										"</div>"
//						);
//					} else { 
//						$(this).before(
//										"<div id='" + obj.r_start_tm + "' class='chatlog receive'>" +
//										"<h5>고객 </h5>"+
//										"<p>"+ 
//										obj.r_stt_text + 
//										"</p>" + 
//										"<span class='time'>" +
//										obj.r_start_tm + "<br>" + obj.r_end_tm + 
//										"</span>" + 
//										"</div>"
//						);
//					}
//					flag = true;
//				}
//			}
//		});
//		return flag;
//	}

</script>
</head>

<body>
	<div>
		<img class="bc_logo" src="/resources/img/logo.png">
		<div class="head_time" id="c_time"></div>
	</div>
	<div class="row">
		<div class="row">
			<div class="side">
				<div class="side_head">
					<img class="bc_title_img" src="/resources/img/icon_callmem.png">
					<div class="bc_title_text_Left" id="callNum"></div>
					<div class="bc_title_text_Left_none" id="uGroup"></div>
					<div class="bc_title_text_left_none" id="uName"></div>
				</div>
				<div class="chatlog" id="chat_Log">
				
					<div class="chatlog_mine">
                        <h5>나</h5>
                        <span class="time">11:20:35<br>11:21:17</span>
                        <p>안녕하십니까? 비씨카드 제휴업체 상담원 상담인입니다.</p>
                    </div>

                    <div class="chatlog_receive">
                        <h5>고객님</h5>
                        <p>네 무슨 일이신데요..제가 지금 바빠서요. 짧게 말씀하세요</p>
                        <span class="time">11:20:35<br>11:21:17</span>
                    </div>

                    <div class="chatlog_mine">
                        <h5>나</h5>
                        <span class="time">11:20:35<br>11:21:17</span>
                        <p>개인정보보호정책이 변경됨에 따라 안내해드리려고 연락드렸습니다. 잠시 통화가능하십니까?</p>
                    </div>

                    <div class="chatlog_receive">
                        <h5>고객님</h5>
                        <p>네 근무시간 중이라 짧게 부탁드립니다</p>
                        <span class="time">11:20:35<br>11:21:17</span>
                    </div>
                    <div class="chatlog_receive">
                        <p>그런데 BC카드 회사 내부 규정인가요? 아니면 정보통신부나 그런 전반적인 규정이 바뀐것인가요?</p>
                        <span class="time">11:20:35<br>11:21:17</span>
                    </div>
                    
                    <div class="chatlog_mine">
                        <h5>나</h5>
                        <span class="time">11:20:35<br>11:21:17</span>
                        <p>개인정보보호정책이 변경됨에 따라 안내해드리려고 연락드렸습니다. 잠시 통화가능하십니까?</p>
                    </div>
                    <div class="chatlog_mine">
                        <span class="time">11:20:35<br>11:21:17</span>
                        <p>개인정보보호정책이 변경됨에 따라 안내해드리려고 연락드렸습니다. 잠시 통화가능하십니까?</p>
                    </div>
                    <div class="chatlog_mine">
                        <span class="time">11:20:35<br>11:21:17</span>
                        <p>개인정보보호정책이 변경됨에 따라 안내해드리려고 연락드렸습니다. 잠시 통화가능하십니까?</p>
                    </div>
                    <div class="chatlog_mine">
                        <span class="time">11:20:35<br>11:21:17</span>
                        <p>개인정보보호정책이 변경됨에 따라 안내해드리려고 연락드렸습니다. 잠시 통화가능하십니까?</p>
                    </div>
				</div>
			</div>
		</div>
		<div class="bc_box bc_box_type">
			<div class="bc_box-in bc_box-in-type">
				<div class="bc_title">
					<div class="bc_title_text_left">상담유형분류</div>
				</div>
				<div class="rule">
					<div style="padding: 10px">
						<table>

							<tbody>
								<tr id="top_1_row">
									<th>
										<div class="selectbox icheck-midnightblue">
											<select id="top_select_1" name="top_select"
												class="top_select_class icheck-midnightblue"
												style="width: 90%; height: 28px;">
												<option value="1" selected>1순위</option>
												<option value="2">2순위</option>
												<option value="3">3순위</option>
											</select>
										</div>
									</th>
									<td>
										<div class="radiotext" id="top_1">
											<label for='policy'></label>
										</div>
									</td>
									<td>
										<div class="radiotext_recommend" style="text-align: right">
											<label for='policy' id="score_1">(추천도 : -%)</label>
										</div>
									</td>
								</tr>

								<tr id="top_2_row">
									<th>
										<div class="selectbox icheck-midnightblue">
											<select id="top_select_2" name="top_select"
												class="top_select_class icheck-midnightblue"
												style="width: 90%; height: 28px;">
												<option value="1">1순위</option>
												<option value="2" selected>2순위</option>
												<option value="3">3순위</option>
											</select>
										</div>
									</th>
									<td>
										<div class="radiotext" id="top_2">
											<label for='product'></label>
										</div>
									</td>
									<td>
										<div class="radiotext_recommend" style="text-align: right">
											<label for='product' id="score_2">(추천도 : -%)</label>
										</div>
									</td>
								</tr>
								<tr id="top_3_row">
									<th>
										<div class="selectbox icheck-midnightblue">
											<select id="top_select_3" name="top_select"
												class="top_select_class icheck-midnightblue"
												style="width: 90%; height: 29px;">
												<option value="1">1순위</option>
												<option value="2">2순위</option>
												<option value="3" selected>3순위</option>
											</select>
										</div>
									</th>
									<td>
										<div class="radiotext" id="top_3">
											<label for='service'></label>
										</div>
									</td>
									<td>
										<div class="radiotext_recommend" style="text-align: right">
											<label for='service' id="score_3">(추천도 : -%)</label>
										</div>
									</td>
								</tr>
								<tr>
									<th colspan="3">
										<div class="icheck-midnightblue"
											style="float: left; padding: 10px Opx 10px 0px;">
											<input type="checkbox" id='search' name="optcheck" value="4"
												onclick="div_Onoff(this.value, 'con');"> <label
												for='search'><span>분류유형 검색어</span></label>
										</div>
										<div class="search-container"
											style="padding: 10px Opx 10px Opx;">
											<input placeholder='검색어' class='js-search' type="text"
												onkeyup="searchCategory(event)" style="ime-mode: active" />
											<i class="fa fa-search"></i>
										</div>
									</th>
								</tr>
								<tr id="srchArea">
									<td colspan="3">
										<div class="radio_etc" id="con" style="visibility: hidden;">
											<table class="etc">
												<tbody>
												</tbody>
											</table>
										</div>
									</td>
								</tr>
							</tbody>
						</table>
					</div>
					<div class="Line"></div>
					<div class="bc_title_text_left" style="padding: 10px Opx 10px Opx;">상담내용
					</div>
					<div style="padding: 10px 10px 20px 10px;">

						<textarea id="ap_memo" class="summary" maxlength="500"></textarea>
					</div>
				</div>
			</div>
		</div>
	</div>
	
	<input id="tempGroupNm" type="hidden" value="" />
	<input id="ap_class_cd1" type="hidden" value="" />
	<input id="ap_class cd2" type="hidden" value="" />
	<input id="ap_class cd3" type="hidden" value="" />
	
</body>
</html>



