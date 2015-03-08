var unless = require("express-unless");
var unique_id = require("./unique_id");

var mainObject = {
	// middleware
	middleware: function() {
		expressHandler.unless = unless;
		return expressHandler;
	},

	// Generate a token
	generateAndSendToken: function(req, storeData) { 
		req.status(200).send({ token: insertToken(storeData) });
	},

	// This handler will be called if no token is available
	noTokenHandler: function(req, res) {
		res.status(403).send({ error: "No token" });
	},

	// Get the token of a request
	getToken: getToken,
	
	// Live time of a token in seconds
	tokenTTL: 60
};

// Current tokens loaded
var currentTokens = [];

function insertToken(obj) {
	var token = unique_id.generate();
	var exp = secondsAfter1970() + mainObject.tokenTTL;
	var data = {};

	if(typeof obj === "object")
		data = obj;

	currentTokens.push({ token: token, exp: exp, data: data });
	return token;
}

function getToken(req, callback) {
	var token = req.get("Authorization");
	if(typeof token !== "string")
		return callback(false);
	
	for(var i = 0; i < currentTokens.length; i++) 
		if(currentTokens[i].token == token) 
			return callback(true, currentTokens[i]);
		
	
	return callback(false);
}

function removeToken(token){
	var idx = currentTokens.indexOf(token);
	if(idx != -1) {
		currentTokens.splice(idx, 1);
		return true;
	}

	return false;
}

function secondsAfter1970() {
	return Math.round(new Date().getTime() / 1000);
}

function expressHandler(req, res, next) {
	getToken(req, function(success, token) {
		if(!success)
			return mainObject.noTokenHandler(req, res);
		 		 
		req.token_ = token;

		req.getTokenData = function() {
			return this.token_.data;
		}

		req.getTokenToken = function() {
			return this.token_.token;
		}

		res.refreshToken = function() {
			if(!req.hasToken) 
				return false;

			req.token_.exp = secondsAfter1970() + mainObject.tokenTTL;
			return true;
		}

		res.removeToken = function() {
			return removeToken(req.token_);
		}

		next();
	});
}

module.exports = mainObject;

// Clean up all unused tokens
setInterval(function() {
	for(var i = 0; i < currentTokens.length; i++) {
		var user = currentTokens[i];

		if(user.exp <= secondsAfter1970()) {
			unique_id.free(user.token);
			currentTokens.splice(i, 1);
			i--;
		}
	}
}, 500);