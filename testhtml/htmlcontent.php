<!DOCTYPE html>
<head>
<meta charset="utf-8">
<!-- <script>
</script> -->
<title>html文本回显</title>
</head>
<body>
<h1 align=center>类型:输入在html文本中回显</h1>
<?php 
ini_set("display_errors", 0);
$str = $_GET["payload"];
echo "<h3 align=center>payload内容为:".$str."</h3>";
?>
</body>
</html>