<!DOCTYPE html>
<head>
<meta charset="utf-8">
<!-- <script>
</script> -->
<title>attribute 属性值回显</title>
</head>
<body>
<h1 align=center>类型:输入在attribute属性值中回显</h1>
<?php 
ini_set("display_errors", 0);
$str = $_GET["payload"];
echo "<img src=xx ttt=$str".">";
?>
</body>
</html>