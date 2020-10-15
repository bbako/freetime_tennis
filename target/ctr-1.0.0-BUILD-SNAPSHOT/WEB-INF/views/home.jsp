<%@ page language="java" contentType="text/html; charset=EUC-KR"
	pageEncoding="EUC-KR"%>
<!DOCTYPE html>
<html>
<head>
	<meta charset="EUC-KR">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<meta name="description" content="">
	<meta name="author" content="">
	<meta http-equiv="Content-Type" content="text/html; charset=EUC-KR">
	
	<link rel="stylesheet" href="/resources/js/bootstrap/css/bootstrap.min.css">
	
	<script type="text/javascript" src="/resources/js/jquery/jquery-3.4.1.min.js"></script>
	<script type="text/javascript" src="/resources/js/bootstrap/js/bootstrap.min.js"></script>
	<title>BC Card</title>

<script type="text/javascript">
	$(document).ready(function () {
		$("#user_id").focus();
	});

	var windows_Popup = null;

	function showPopup() {
		
		console.log($("#user id").val());
		
		var url = "/csuiUser.do?user_id=" + $("#user_id").val();
		var title = $("#user_id").val();
		var status = "width=500, height=1108, scrollbars=yes, resizable=1, location=no, directories=no, titlebar=no, status=no";

		windows_Popup = window.open(url, title, status);
	}

	function goManage() {
		$("#useridPost").val($("#user_id").val());
		$('#form1').submit();
	}
	
	function goDashBoard() {
		window.location.href = "/dashBoard.do"
	}
	
	function goRecognition() {
		window.location.href = "/recognition.do"
	}
</script>

</head>

<body class="Login">

	<form id="form1" method="POST" action="/csuiManager.do">
		<input type="hidden" id="useridPost" name="user_id">
	</form>
	<div id="container" class="LogCont">
		<div class="content">
			<h1 class="logo"></h1>

			<div class="Logwrap">
				<div class="LogIptlst">
					<input type="text" id="user_id" title="id" placeholder="User ID" value="20200000">
				</div>
				<br>
				<div>
					<button onclick="showPopup();" class="btn-lg btn-info">상담사</button>
					<button onclick="goManage();" class="btn-lg btn-danger">관리자</button>
					<button onclick="goDashBoard();" class="btn-lg btn-success" >대시보드</button>
					<button onclick="goRecognition();" class="btn-lg btn-primary" >인식률측정</button>
				</div>
			</div>
		</div>
		<div>
		</div>
	</div>
</body>
</html>



