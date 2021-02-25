<!DOCTYPE html>
<head>
<meta charset="utf-8">
<!-- <script>
</script> -->
<title>attribute 特殊属性名回显</title>
</head>
<body>
<h1 align=center>类型:输入在attribute属性值中回显而属性名为特殊属性名</h1>
<?php 
$str = $_GET["payload"];
echo "<img src=XX onerror=".$str.">";
?>
</body>
</html>