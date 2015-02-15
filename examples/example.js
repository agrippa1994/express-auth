var app = require("express")();
var cors = require("cors");
var bodyParser = require("body-parser");
var auth = require("../lib/auth.js");

//	Enable CORS
app.use(cors());
app.use(bodyParser.json()); 

//	Every path needs a token except '/generate_token'
app.use(auth.handler().unless( {path: [ "/generate_token" ] })); 

//	The url '/' can only be called if the request header will provide the token
//	generated by '/generate_token'
//	The client must submit the token via 'Authorization' in the HTTP header
//	E.g Authorization: [token]
app.get("/", function(req, res){

	//	Refresh the token to avoid expiration
	res.refreshToken();

	//	Send the secret data to the client
	res.send(req.getTokenData());
});

//	Generate a token for the client
app.get("/generate_token", function(req, res) {

	//	The second parameter's object is stored server-side
	//	and can be used to hold sensible data.
	//	Tokens can be used to identify connections
	auth.generateAndSendToken(res, { secretData: "Hello world" });
});

app.listen(3000);