<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta http-equiv="X-UA-Compatible content=" IE=edge, chrome=1">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>BC Card</title>
<link rel="stylesheet"	media="(min-width: 651px) and (max-width: 5000px)"	href="/resources/css/admin.css">
<link rel="stylesheet" media="(min-width: 0px) and (max-width: 650px)"	href="/resources/css/adminv03_SmallBtn.css">
<link rel="stylesheet" href="/resources//css/adminV03_1Chat.css">
<link rel="stylesheet" href="/resources//css/adminV03 2Table.css">
<link rel="stylesheet" href="/resources//css/adminto3 3Radiobtn.css">
<link rel="stylesheet" href="/resources//css/adminV03 4Btn.css">
<script type="text/javascript"	src="/resources/js/jquery/jquery-1.10.2.min.js"></script>
<style>
	html, body {
		font-family: " Noto Sans KR ', sans-serif;
	}
	
	.closebtn {
		display: block;
		color: #000;
	}
	
	fas .fa-user {
		margin: 0 12px;
		color: #5ab9ea
	}
</style>

<script> 

	var windows Popup = new Array();
	var whereId = 0; 
	var tempArray = new Array();
	var orgIdArray = new Array();
	
	$(document).ready(function() {
		
		setInterval(function(){
			startTime(); 
		},500); 
		sendPing();
		getUserCnt();

		var u_list = JSON.parse('${u_list}');
		makeLeftList(u_list);

		$("#s_name").keyup(function(e) {
			if(e.keyCode == 13) {
				var u_list_filter2 = JSON.parse('${u_list}').filter(function(user){
					return user.username.indexOf($("#s_name").val())>=0;
				});

				$("#leftList").html(""); 
				makeLeftlist(u_list_filter2);

				if($("#s_name").val().length > 0){
					$(".accordion").click();
				}
			}
		});

		$("#ap_memo").bind("change", function() {
			var apMemoText = $("#ap_memo").val(); 
			if(apMemoText.length > 500) {
				alert(" 상담내용은 500자 이하 입력 가능합니다."); 
				$("#ap_memo").val("");
				$("#ap_memo").focus();
			}
		});

		function makeLeftList(u_list) {
			var u_team = ""; 
			for(var i = 0; i < u_list.length ; i++) {
				var user = u_list[i];
				
				if(u_team != user.orgid){
					orgIdArray.push(user.orgid); 
					u_team = user.orgid; 
					
					$("#leftList").append( 
											"<button class='accordion' onclick='openAccodion(this)'>"
											+ "<span>" + user.orgnm + "</span><br>"|
											+ "<span style='font-size12px; float:left; padding-top:2%;'>(실 "+ user.stt_use_cnt + "명 / 총" +  user.team_cnt + "명)</span>"
											+ "</button >"
											+ "<ul class='panel' id='panel_" + user.orgid + "'></ul>"
					)
				};
			
				if(user.stt_use_yn == 1) {
					if(user.call_status == "1") { 
						$("#panel_"+ user.orgid +"").append(
												"<li class='icheck-midnightblue'>"
												+ "<input class='u_check' style='display:none;' type='checkbox' name='group" + user.orgid +"' id='member_" + user.userid + "'>"
												+ "<label for='member" + user.userid + "' onclick= userNewWin(" + user.userid + ")'></label>"
												+ "<img id='call_"+ user.userid +"' src='/resources/img/icon_callmem.png' style='width:20px;' alt=''>"
												+ "<span class='userli' style='font-size:0.9em' onclick='userClick(\"" + user.userid + "\")'>" + user.username + " (" + user.userid + ")</span >"
												+ "</li>" );
					}else{
						$("#panel_"+ user.orgid +"").append(
													"<li class='icheck-midnightblue'>"
													+ "<input class='u_check' style='display:none;' type='checkbox' name='group" + user.orgid +"' id='member_" + user.userid + "'>"
													+ "<label for='member" + user.userid + "' onclick= userNewWin(" + user.userid + ")'></label>"
													+ "<img id='call_"+ user.userid +"' src='/resources/img/icon_callmem.png' style='width:20px;' alt=''>"
													+ "<span class='userli' style='font-size:0.9em' onclick='userClick(\"" + user.userid + "\")'>" + user.username + " (" + user.userid + ")</span >"
													+ "</li>" );
					}
				}else{ 
					$("#panel_"+ user.orgid +"").append(
					"<li class='icheck-midnightblue'>"
					+ "<input class='u_check' style='display:none;' type='checkbox' name='group" + user.orgid +"' id='member_" + user.userid + "'>"
					+ "<label for='member" + user.userid + "' onclick= userNewWin(" + user.userid + ")'></label>"
					+ "<img id='call_"+ user.userid +"' src='/resources/img/icon_callmem.png' style='width:20px;' alt=''>"
					+ "<span class='userli' style='font-size:0.9em' onclick='userClick(\"" + user.userid + "\")'>" + user.username + " (" + user.userid + ")</span >"
					+ "</li>" );
					
					// connectWebSocket4Manager(orgIdArray);
				}
			}
		};

		function openAccodion(el){
			el.classList.toggle("active"); 
			var panel = el.nextElementSibling;
			if (panel.style.maxHeight) {
				panel.style.maxHeight = null; 
			} else {
				panel.style.maxHeight = panel.scrollHeight + "px";
			}
		};

		function userNewwin(user) {
			if($("input:checkbox[id=\"member_"+ user +"\"]").is(":checked")) {
				closePopup(user); 
			} else {
				showPopup(user);
			}
		};

		function showPopup(user) {
			tempArray.push(user);
			var url = "/csuiUser.do?user_id=" + user;
			var title = user;
			var status = "width=500, height=1000, left="+ 100*tempArray.length + ", top=0, scrollbars =1 , resizeable=1, location=no, directories=no, titlebar=no, status=no";
			windows Popup[whereId] = window.open(uri, title, status); 
			whereId = whereId +1;
		};
			
		function closePopup(value) {
			var i = tempArray.indexOf(value);
			if(i >=0){
				windows Popup[i].window.close(); 
				tempArray[i] = '00000000';
			}
		};

		function startTime() {

			var today = new Date(); 
			var year = today.getFullYear(); 
			var month = checkTime (today.getMonth() + 1);
			var date = checkTime (today.getDate()); 
			var day = today.getDay(); 
			var hour = checkTime (today.getHours()); 
			var min = checkTime(today.getMinutes()); 
			var sec = checkTime(today.getSeconds()); 
			var week = new Array('일','월','화','수','목','금','토'); 
			var dayLabel = week[day];
			
			$("#c_time").html( 
							'<span style="color:black; font-size: 13px">' + year + '-'
							+ month + '-' + date + '(' + dayLabel + ') ' + hour
							+ ':' + min + ':' + sec + '</span>'); 
		};

		function checkTime(i) {
			if (i < 10) {
				i = "0" + i;
			}
			return i;
		};

		function userClick(userid) {
			$(".chatlog").empty();
			connectWebSocket(userid);
		}
		
		
		function getWFMSInfo(userid) { 
			$.ajax({
				type : 'POST', 
				url : '/getWFMSInfo.do', 
				dataType : 'Json', 
				data : {
					user_id : userid
				},
				error : function(XMLHttpRequest, textStatus, errorThrown) {
					console.log("error");
				},
				success : function(data) {
					$("#uGroup").html("|" + data[0].orgnm); 
					$("#uName").html("1" + data[0].username); 
					$("#tempGroupNm").val(data[0].orgnm);
				}
			})
		};

		function getUserCnt() { 
			$.ajax({
				type: 'POST', 
				url : "/getUserCnt.do', 
				dataType : 'Json',
				data : {
					user_id : ${user_id}, 
					user_duty_cd : ${user_duty_cd}, 
				},
				error : function(XMLHttpRequest, textStatus, errorThrown) {
					console.log("error"); 
				}
				success : function(data) {
					$("#stt_user").html(data[0].STT_USER); 
					$("#total_user").html(data[0].TOTAL_USER);
				}
			});
		};
		

		function getchat(userid) { 
				exSocket.send (JSON.stringify({
					type : "user_id", 
					r_csr_id : userid, 
					level : "1"
				}));
		};

		function getcallstatus4Manager(orgid) { 
				exSocket4Manager.send(JSON.stringify({
					type : "user_id", 
					group_id : orgid, 
					level : "2"
				}));
		};

		var exSocket = null; 
		var exSocket4Manager = null;
		
		function sendPing() {
			console.log("ping!!!! :" + exSocket + ", " + exSocket4Manager);

			if (exSocket != null) { 
				exSocket.send(JSON.stringify({
					type : "ping" 
				}));
			}
				
			if (exSocket4Manager != null) { 
				exSocket4Manager.send(JSON.stringify({
					type : "ping4Manager" 
				})); 
			}else{
				connectWebSocket4Manager(orgIdArray);
			}

			var t = setTimeout(sendPing, 20000);
		};

		function connectWebSocket(userid) {
			if (exSocket == null) {
				exSocket = new WebSocket("${wssUrl}") 
				exSocket.onopen = function(event) {
					getchat(userid);
				}
				exsocket.onclose = function(event) {
					exSocket = null;
				}
				exSocket.onmessage = function(event) {
					var jsonData = JSON.parse(event.data);
					console.log(jsonData);

					if (jsonData.type == "call_start") {
						$(".chatlog").empty(); 
						$("#callNum").html(jsonData.r_cid);
						$("#ap_class_cd1").val('');
						$("#ap_class_cd2").val('');
						$("#ap_class_cd3").val('');
						$("#ap_memo").val("");
						$("#top_1").text(' ');
						$("#top_2").text(' ');
						$("#top_3").text(');
						$("#score_1").text('');
						$("#score_2").text('');
						$("#score_3").text('');
					} else if (jsonData.type == "call_end") {
						 //TA 요청 부분
					} else if (jsonData.type == "call text") {
						for (var i = 0; i < jsonData.data.lengths ; ++i) {
							var rtobj = getSelctor(jsonData.data[i]); 
							if (rtobi) { } else {
								if (jsonData.data[i].r_mode_cd == '1') {
									$(".chatlog").append(
										"<div id='" + jsonData.data[i].r_start_tm_order + "'class='chatlog_mine'><h5>4</h5><span class='time'>"
										+ jsonData.data[i].r_start_tm 
										+ "<br>" 
										+ jsonData.data[i].r_end_tm 
										+ "</spa><p>" 
										+ jsonData.data[i].r_stt_text
										+ "</p></div>") 
								} else { 
									$(".chatlog") .append(
										"<div id='" + jsonData.data[i].r_start_tm_order + ".class='chatlog_receive'><h5>고객</h5>"
										+ "<p>"
										+ jsonData.data[i].r_stt_text 
										+ "</p>" 
										+"<span class='time'>"
										+ jsonData.data[i].r_start_tm 
										+ "<br>"
										+ jsonData.data[i].r_end_tm 
										+ "</span>" 
										+"</div>");
								}
							}
						}
					} else {
						$(".result").val(jsonData.data);
					}
					$("#chatlog").scrollTop($("#chatlog")[0].scrollHeight);
				};
			}else{
				getchat(userid);
			}
		}

		function getselctor(obj) {
			
			var time = obj.r_start_tm_order; 
			var flag = false;

			$("#chatlog div").each(
				function() {
					var preTime = $(this).attr('id');

					if (!flag) { 
						if (obj.r_mode_cd == '1') { 
							$(this).before(
								"<div id='" + obj.r_start_tm + "' class='chatlog_mine'><h5>4</h5><span class='time'>"
								+ obj.r_start_tm 
								+ "<br>"
								+ obj.r_end_tm  
								+ "</span><p>" 
								+ obj.r_stt_text
								+ "</p><</div>"); 
						} else { 
							$(this).before(
								"<div id='" + obj.r_start_tm + "'class='chatlog_receive'><h5>고객</h5>" 
								+ "<p>"
								+ obj.r_stt_text 
								+ "</p> 
								+"<span class='time'>"
								+ obj.r_start_tm
								+ "<br>"
								+ obj.r_end_tm 
								+ "</span> 
								+"</div>");
						}
						flag = true;
					}
				});
				return flag;
			};

			function connectWebSocket4Manager (orgIdArray) {
				if (exSocket4Manager == null) {
					exSocket4Manager = new WebSocket("${wssUrl}"); 
					exSocket4Manager.onclose = function(event) {
						exSocket4Manager = null;
					}
					exSocket4Manager.onopen = function(event) {
						getCallstatus4Manager (orgIdArray);
					}
					exSocket4Manager.onmessage = function(event) {
						var jsonData = JSON.parse(event.data);
						console.log(jsonData);
						$("#call_"+jsonData.r_csr_id).attr("src", "/img/icon_callmemNot.png" )
				}else{
				}
			};
		}
	}
		
	var leftListFlag = 0;

	function leftlistDropDown() {
		if(leftListFlag == 0 ) {
			$('#leftListDropDown').removeClass('accordionoff'); 
			$('#leftlistDropDown').addClass('accordionon);
			$('.navbar').removeClass('hidden');
			leftListFlag = 1; 
		}else{
			$('#leftListDropDown').removeClass('accordionOn'); 
			$('#leftListDropDown').addClass('accordionoff');
			$('.navbar').addClass('hidden'); 
			leftListFlag = 0;
		}
	};
</script>
</head>

<body style="-ms-overflow-style: none;">
	<div class="wrapper">
		<div class="left-out">
			<div class="left">
				<div>
					<h3 class="Logozone" style="margin-left: 5px; margin-top: 5px;"></h3>
					<button id="leftlistDropDown" class="accordionoff" onclick="leftlistDropDown();"></button>
					<div style="clear: both;"></div>
				</div>

				<div class="navbar hidden searchBar">
					<div>
						<p style="top: 1%; text-align: center; padding-top: 10px; position: relative;">
							<span> 실시간 상담사</span>
							<span style="padding: opx; font-size: 18px; font-weight: bold; color: #F49760" id="stt_user">0 </span> 
							<span style="padding: 0px;">명 / 총 </span>
						</p>
					</div>
					<br>
				</div>
				<div id="leftlist" class="leftlist"></div>
			</div>
		</div>
	</div>
	<div class="side-out">
		<div class="side">
			<div class="side_head">
				<h3>
					<img src="img/icon_callmem.png" alt="상담사 아이콘" align="left">
					<span id="callium"></span> &nbsp; 
					<span id="uGroup" style="padding: 0px"></span>
					<span id="uName" style="padding: 0px"></span>
					<div class="head_time" id="c_time"></div>
				</h3>
				<div class="head line"></div>
			</div>
			<div class="chotlog" id="chatlog"
				style="-ms-overflow-style: none; height: 760px;"></div>
		</div>
		<div class="main-out">
			<div class="main">
				<div class="side_head">
					<h3>
						<span>상담유형분류</span>
					</h3>
					<div class="head_Line"></div>
				</div>
				<div class="rule">
					<h3>상담유형 자동 추천</h3>
					<table class="table-responsive">
						<tbody>
							<tr id="top_1_row">
								<th><label for='policy'><span>1순위</span></label></th>
								<td>
									<div class="radiotext" id="top_1">
										<label for='policy'></label>
									</div>
								</td>
								<td>
									<div class="radiotext_recommend" style="text-align: right">
										<label for="policy" id="score_1">(추천도 : -%)</label>
									</div>
								</td>
							</tr>
							<tr id="top_2_row">
								<th><label for='product'><span>2순위</span></label></th>
								<td>
									<div class="radiotext" id="top_2">
										<label for='product'></label>
									</div>
								</td>
								<td>
									<div class="radiotext_recommend" style="text-align: right">
										<label for='product' id="score_2">(추천도 : %)</label>
									</div>
								</td>
							<tr id="top_3_row">
								<th><label for='service'><span>3순위</span></label></th>
								<td>
									<div class="radiotext" id="top_3">
										<label for='service'></label>
									</div>
								</td>
								<td>
									<div class="radiotext_recommend" style="text-align: right">
										<label for='service' id="score_3">(추천도: -%)</label>
									</div>
								</td>
							</tr>
							<tr>
								<td colspan="3">
									<div class="line"></div>
								</td>
							</tr>
							<tr>
								<td colspan="3">
									<div>
										<h3>상담내용</h3>
										<textarea id="ap_memo" class="summary" disabled="disabled" rows="15" maxlength="500"></textarea>
									</div>
								</td>
							</tr>
						</tbody>
					</table>
				</div>
			</div>
		</div>
	</div>

	<input type="hidden" id="tempGroupNm" value="" />
	<input type="hidden" id="ap_class_cd1" value="" />
	<input type="hidden" id="ap_class_cd2" value="" />
	<input type="hidden" id="ap_class_cd3" value="" />

</body>
</html>
