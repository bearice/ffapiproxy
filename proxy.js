#!/usr/bin/env node 

var qs = require('querystring');
var url = require('url');
var http = require('http');

var SQLite3 = require('./libs/node-sqlite3/sqlite3').verbose();
var KumaServer = require('./libs/kumachan4js/server');
var OAuth   = require('./libs/oauthjs/oauth');
var config  = require('./config');

var db = new SQLite3.Database('oauth_token.db');

function login(req,resp){
	var oa = new OAuth(config.oauth);
    req.session.set("OAuth",oa);
    oa.acquireRequestToken(null, function(oa){
    	if(!oa.statusCode){
    	    var oauth_callback = config.oauth.callbackURI || "http://"+req.headers['host']+"/verify";
            var oauth_url = oa.getAuthorizeTokenURI({
            	'oauth_callback': oauth_callback
            });
            resp.writeHead(301,{'location':oauth_url});
            resp.end("<html><body><a href=\'"+ oauth_url +
            "\'>Click here to login with OAuth</a></body></html>");
        }else{
            resp.writeHead(500);
            resp.end(String(oa));
        }
    });
}

function logout(req,resp){
    req.session.clear();
    resp.writeHead(302, { "Location": "/" });
    resp.end();
}

function verify(req,resp){
    var oa = req.session.get("OAuth");
    //console.info(oa);
    var token = req.info.query.oauth_verifier;
    if(oa){
        oa.setOAuthVerifier(token);
        oa.acquireAccessToken(function(oa){
        	if(!oa.statusCode){
                var header = oa.generateAuthorizationString(
                    "GET","http://"+config.server+"/account/verify_credentials.json",{}
                );
                
                var options = {
                    host: config.server,
                    port: 80,
                    path: '/account/verify_credentials.json',
                    method: 'GET',
                    headers:{
                        'Authorization'  : header
                    },
                };
                var data = "";
                http.request(options, function(res) {
                    res.setEncoding('utf8');
                    res.on('data', function (chunk) {
                        data += chunk;
                    });
                    res.on('end', function(){
                    	try{
                    		data = JSON.parse(data);
                    		oa.user_detail = data;
                    	}catch(e){
                    		console.error(e);
                        }
                        resp.writeHead(302, { "Location": "/" });
                        resp.end();
                    });
                }).end();
            }else{
                resp.writeHead(500);
                resp.end(String(oa));
            }
        });
    }else{
        resp.writeHead(302, { "Location": "/login" });
        resp.end();
    }
}


function check_session(req,resp){
	var obj = {};
    function end(){
        resp.setHeader("Content-Type","application/json");
        resp.setHeader("Cache-Control","no-cache");
        resp.end(JSON.stringify(obj));
    }

    var oa = req.session.get("OAuth");
    if(oa && oa.user_detail){
        obj.login = true;
        obj.name  = oa.user_detail.id
        db.get("SELECT password FROM tokens WHERE loginname=?",obj.name,function(err,row){
            if(row){
                obj.passwd = row.password;
            }else if(err){
                console.error("getOAuthParam",auth,err);
            }
            end();
        });
    }else{
        obj.login = false;
        obj.name  = null;
        end();
    }
}

function reset_passwd(req,resp) {
    var obj = {};
    function end(){
        resp.setHeader("Content-Type","application/json");
        resp.setHeader("Cache-Control","no-cache");
        resp.end(JSON.stringify(obj));
    }

    var oa = req.session.get("OAuth");
    //console.info(oa);
    var passwd = saveOAuthParam(oa);

    resp.writeHead(302, { "Location": "/" });
    resp.end();
    return;

    if(passwd){
        obj.login = true;
        obj.name   = oa.user_detail.id;
        obj.passwd = passwd;
    }else{
        obj.login = false;
    }
    end();
}

function randomString() {
	var chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz";
	var string_length = config.pwdLen || 16;
	var randomstring = '';
	for (var i=0; i<string_length; i++) {
		var rnum = Math.floor(Math.random() * chars.length);
		randomstring += chars.substring(rnum,rnum+1);
	}
    return randomstring;
}

function saveOAuthParam(oa){
    if(oa && oa.user_detail){
        var obj = {
            $loginname   : oa.user_detail.id,
            $password    : randomString(),
            $oauth_token : oa.oauthToken,
            $oauth_secret: oa.oauthTokenSecret,
        };
        db.run("INSERT INTO tokens(loginname,password,oauth_token,oauth_secret) VALUES( $loginname, $password, $oauth_token, $oauth_secret )",obj);
        return obj.$password;
    }
    return false;
}

function getOAuthParam(auth,cb){
    if(!/^Basic [0-9a-zA-Z=+\/]+$/.test(auth)){
        //console.info("Bad auth:",auth);
        cb(null);
        return;
    }

    auth = new Buffer(auth.substr(6),'base64').toString('utf8');
    auth = auth.split(":");

    db.get("SELECT oauth_token,oauth_secret FROM tokens WHERE loginname=? and password=?",auth,function(err,row){
        var oauth = null;
        if(row){
            oauth = new OAuth(config.oauth);
            oauth.oauthToken = row.oauth_token;
            oauth.oauthTokenSecret = row.oauth_secret;
        }else if(err){
            console.error("getOAuthParam",auth,err);
        }
        cb(oauth);
    });
}
function proxy(req,resp){
    if(config.filter && !(config.filter.test(req.url))){
    	resp.writeHead(403, { "X-Error": "filtered by admin" });
        resp.end();
        console.info("Forbidden: "+req.url);
        return;
    }
    var postData = null;
    var contentLength;
    if(req.method=="POST"){
        contentLength = req.headers['content-length'];
        if(contentLength===undefined){
            resp.writeHead(400, { "X-Error": "Missing Content-Length" });
            resp.end();
            console.info("Bad POST");
            return;
        }
        req.on('end',function(){do_req();});
        if(req.headers['content-type'] == 'application/x-www-form-urlencoded'){
            req.setEncoding('utf8');
            postData = "";
            req.on('data',function(data){
                postData += data;
            });
        }else{
            req.setEncoding(null);
            postData = new Buffer(parseInt(contentLength));
            var idx = 0;
            req.on('data',function(data){
                idx += data.copy(postData,idx);
            });
        }
    }else{
         do_req();
    }
    function do_req(){
        var auth = req.headers['authorization'];
        getOAuthParam(auth,function(oa){
            if(auth && !oa){
                resp.writeHead(401, { "X-Error": "Bad Authorization" });
                resp.end();
                return;
            }
            cReq = {};
            cReq.method = req.method;
            cReq.host = config.server;
            cReq.port = 80;
            cReq.path = req.url;
            cReq.headers = {}
            for(k in req.headers){
            	if(!/^host|connection|x-forwarded-for|accept-encoding|cookie$/.test(k))
                    cReq.headers[k] = req.headers[k];
            }
            cReq.headers ["X-Forwarded-For"]=req.headers['x-forwarded-for'] || req.connection.remoteAddress;
             
            if(oa){
                var _url = "http://"+config.server+req.url;
                var param = req.info.query;
                if(typeof(postData)=='string'){
                    var postparam = qs.parse(postData);
                    for(k in postparam)
                        param[k] = postparam[k];
                }
                var header = oa.generateAuthorizationString(cReq.method,_url,param);
                cReq.headers['Authorization']=header;

                //for debug use
                resp.setHeader("X-OAuth-Applied","Yes");
                //var baseString = oa.debugGenerateBaseString(cReq.method,_url,param);
                //resp.setHeader("X-OAuth-BaseString",baseString);
            }

            if(req.method=='POST'){
                cReq.headers['Content-Type']   = req.headers['content-type'];
                cReq.headers['Content-Length'] = req.headers['content-length'];
            }

//            console.info(cReq);
            http.request(cReq, function(cres) {
                cres.on('error',function(e){
                    resp.writeHead(502, { "X-Error": "Bad Gateway" });
                    resp.end(e.toString());
                });
                resp.writeHead(cres.statusCode);
                cres.pipe(resp);
            }).end(postData);  //http.request
        });//getOAuthParam
    };//function do_req
}

var dispatch = [
    '/login'         , login,
    '/logout'        , logout,
    '/verify'        , verify,
    '/check_session' , check_session,
    '/reset_passwd'  , reset_passwd,
    '/'              , null ,
    '/favicon.ico'   , null ,
    '/loading.gif'   , null ,
    /^\/static\/.*$/ , null , //null for static file access
    /.*/             , proxy,
];

var server = KumaServer(dispatch,config.cookies_key,config.session,"ffapiproxy/1.0");
server.listen(config.httpd.port,config.httpd.host);

console.log('Server running at %s:%d',config.httpd.host,config.httpd.port);

