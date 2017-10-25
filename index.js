var express = require('express');
var app = express();
var bodyParser = require('body-parser')
var authentication = require('express-authentication');
var jwt = require('jsonwebtoken');
var util = require('util');
const crypto = require('crypto');
var path = require('path');
var fs = require('fs');
var bcrypt = require('bcrypt');
var formidable = require('express-formidable');
var moment = require('moment');
var recaptcha = require('express-recaptcha');
var cachecontroller = require('express-cache-controller');
var requestC = require('request');
var cors = require('cors');
var compression = require('compression')
var ejs = require('ejs')
var constants = require('./constants');
var classes = require('./classes');
var warnings = require('./warnings');
var language = new warnings.Turkish();

app.enable('trust proxy'); // only if you're behind a reverse proxy (Heroku, Bluemix, AWS if you use an ELB, custom Nginx setup, etc) 

//app.use(limiter);

app.all('*', cors());
// app.use (function (request, response, next) {
// 	constants.Redirect(request, response, next);
// });

app.set('port', (process.env.PORT || 5000));
app.use(express.static(__dirname + '/public'));
// views is directory for all template files
app.set('views', __dirname + '/views');
app.set('view engine', 'ejs');
app.use(bodyParser.json({
	limit: '4mb'
})); // to support JSON-encoded bodies
app.use(bodyParser.urlencoded({ // to support URL-encoded bodies
	extended: true,
	limit: '4mb'
}));
app.use(compression());
app.use(cachecontroller({
	maxAge: 2592000
}));

function encrypt(message, key) {
	var algorithm = 'aes-256-cbc';
	var clearEncoding = 'utf8';
	var cipherEncoding = 'hex';
	//If the next line is uncommented, the final cleartext is wrong.
	//cipherEncoding = 'base64';
	var cipher = crypto.createCipher(algorithm, key);
	var cipherChunks = [];
	cipherChunks.push(cipher.update(message, clearEncoding, cipherEncoding));
	cipherChunks.push(cipher.final(cipherEncoding));
	var encstr = cipherChunks.join('');
	return encstr;
}

function decrypt(message, key) {
	var decstr = "response";
	try {
		var algorithm = 'aes-256-cbc';
		var clearEncoding = 'utf8';
		var cipherEncoding = 'hex';
		var cipherChunks = [message];
		var decipher = crypto.createDecipher(algorithm, key);
		var plainChunks = [];
		for (var i = 0; i < cipherChunks.length; i++) {
			plainChunks.push(decipher.update(cipherChunks[i], cipherEncoding, clearEncoding));
		}
		plainChunks.push(decipher.final(clearEncoding));
		var decstr = plainChunks.join('');
	}
	catch (err) {
		console.log("An error occured while decryption " + err);
	}
	return decstr;
}

function generateJWTTokenForForgottenPassword(name, valid) {
	var token = jwt.sign({
		username: name,
		valid: valid,
		expiresIn: 43200
	}, process.env.JWTTOKENFORFORGOTTONPASSWORD_KEY);
	return token;
}

function generateJWTToken(name, valid) {
	var token = jwt.sign({
		username: name,
		valid: valid,
		expiresIn: 43200
	}, process.env.JWTTOKEN_KEY);
	return token;
}

function generateLogoutJWTToken(name) {
	var token = jwt.sign({
		username: name,
		expiresIn: -3600
	}, process.env.JWTTOKEN_KEY);
	return token;
}

var authentication = function (request, response, next) {
	try {
		var body = request.body;
		var u_token = body.u_token;
		var decu_token = decrypt(u_token, constants.ENCRYPTION_KEY_TOKEN);
		if (null == u_token) {
			u_token = request.fields.u_token;
			if (null == u_token) {
				return response.json({
					"status": language.error_title,
					"message": language.error_invalidtoken
				});
			}
		}
		jwt.verify(decu_token, process.env.JWTTOKEN_KEY, function(err, decoded) {
			if (err) { //failed verification.
				return response.json({
					"status": language.error_title,
					"message": language.error_invalidtoken
				});
			}
			var expdate = decoded.expiresIn;
			var iat = decoded.iat;
			var u_valid = decoded.valid;
			if (u_valid == 0 || u_valid == null) {
				return response.json({
					"status": language.error_title,
					"message": language.error_invaliduser + language.error_logoutscript
				});
			}
			if (Math.floor(Date.now() / 1000) - iat > expdate) {
				request.body['status'] = language.error_title;
				request.body['message'] = language.error_loginexpired + language.error_logoutscript
				return response.json({
					"status": language.error_title,
					"message": language.error_loginexpired + language.error_logoutscript
				});
			}
			else {
				var querySelectUser =
					"SELECT users.u_id, users.u_name, users.u_photo, SUM(messages.message_unread) AS u_unreadmessage, "
					+"(SELECT SUM(unreadbids) "
						+"FROM (SELECT SUM(DISTINCT bids.receiver_bidunread) AS unreadbids "
								+"FROM users "
								+"JOIN bids ON (users.u_id = bids.receiver_id) "
								+"JOIN item_bids_relation ON (bids.bid_id = item_bids_relation.bid_id) "
								+"JOIN items ON (item_bids_relation.bids_itemid = items.item_id AND items.item_deleted = 0) "
								+"LEFT JOIN user_relations ON user_relations.relation_type = 'Block' AND user_relations.relation_deleted = '0' AND ((users.u_id = user_relations.user_id AND bids.bidder_id = user_relations.related_user_id) OR (users.u_id = user_relations.related_user_id AND bids.bidder_id = user_relations.user_id)) "
								+"WHERE (u_token = " + constants.pool.escape(u_token) + " AND user_relations.related_user_id IS NULL) "
								+"GROUP BY item_bids_relation.bid_id "								
								+"UNION ALL "
								+"SELECT SUM(DISTINCT bids.bidder_bidunread) AS unreadbids "
								+"FROM users "
								+"JOIN bids ON (users.u_id = bids.bidder_id) "
								+"JOIN item_bids_relation ON (bids.bid_id = item_bids_relation.bid_id) "
								+"JOIN items ON (item_bids_relation.bids_itemid = items.item_id AND items.item_deleted = 0) "								
								+"LEFT JOIN user_relations ON user_relations.relation_type = 'Block' AND user_relations.relation_deleted = '0' AND ((users.u_id = user_relations.user_id AND bids.receiver_id  = user_relations.related_user_id) OR (users.u_id = user_relations.user_id AND bids.receiver_id  = user_relations.related_user_id)) "
								+"WHERE (u_token = " + constants.pool.escape(u_token) + " AND user_relations.related_user_id IS NULL) "
								+"GROUP BY item_bids_relation.bid_id) "								
								+"AS unreadbidstable) AS u_unreadbids "
					+"FROM users "
					+"JOIN messages ON users.u_id = messages.to_uid "
					+"LEFT JOIN user_relations ON user_relations.relation_type = 'Block' AND user_relations.relation_deleted = '0' AND ((users.u_id = user_relations.user_id AND messages.u_id = user_relations.related_user_id) OR (users.u_id = user_relations.related_user_id AND messages.u_id = user_relations.user_id)) "
					+"WHERE (u_token = " + constants.pool.escape(u_token) + " AND users.u_id = messages.to_uid AND user_relations.related_user_id IS NULL)";
				constants.pool.query(querySelectUser, function(err, rows) {
					if (!err) {
						var resultLength = rows.length;
						if (resultLength > 0) {
							var tokenOwner = rows[0]['u_name'];
							var tokenOwnerId = rows[0]['u_id'];
							var unreadmessage = rows[0]['u_unreadmessage'];
							var userphoto = rows[0]['u_photo'];
							var unreadbids = rows[0]['u_unreadbids'];
							if (tokenOwner == null || tokenOwnerId == null || userphoto == null) {
								request.body['message'] = language.error_title;
								request.body['status'] = language.error_database;
								request.body['error'] = err;
								return response.json({
									"status": language.error_title,
									"message": language.error_loginexpired + language.error_logoutscript
								});
							}
							request.body['message'] = language.success_title;
							request.body['username'] = tokenOwner;
							request.body['u_id'] = tokenOwnerId;
							request.body['u_unreadmessage'] = unreadmessage;
							request.body['u_photo'] = userphoto;
							request.body['u_unreadbids'] = unreadbids;
							return next();
						}
						else {
							request.body['message'] = language.error_title;
							request.body['status'] = language.error_database;
							request.body['error'] = err;
							return response.json({
								"status": language.error_title,
								"message": language.error_database,
								"response": err
							});
						}
					}
					else {
						request.body['message'] = language.error_title;
						request.body['status'] = language.error_database;
						request.body['error'] = err;
						return response.json({
							"status": language.error_title,
							"message": language.error_database,
							"response": err
						});
					}
				});
			}
		});
	}
	catch (err) {
		response.json({
			"status": language.error_title,
			"message": language.error_unknownerror
		});
	}
}

function checkImageType(input) {
	var lowerCase = input.toLowerCase();
	var tempStrForImageCheck = lowerCase.substring(lowerCase.indexOf(":"), lowerCase.indexOf("/"));
	var extension;
	if (tempStrForImageCheck.indexOf("image") !== -1) {
		var tempStrForExtCheck = lowerCase.substring(lowerCase.indexOf("/"), lowerCase.indexOf(";"));
		if (tempStrForExtCheck.indexOf("png") !== -1) {
			//console.log(tempStrForExtCheck.indexOf("png"));
			extension = "png"
		}
		else if (tempStrForExtCheck.indexOf("jpg") !== -1) {
			//console.log(tempStrForExtCheck.indexOf("jpg"));
			extension = "jpg"
		}
		else if (tempStrForExtCheck.indexOf("jpeg") !== -1) {
			//console.log(tempStrForExtCheck.indexOf("jpeg"));
			extension = "jpeg"
		}
		else {
			extension = "tiff";
		}
	}
	else {
		extension = "response";
	}
	return extension;
}

function insertNewItem(request, response) {
	var imageUploadCheck = true;
	var imageTypeCheck = true;
	var body = request.body;
	var item_name = constants.pool.escape(body.item_name);
	var item_desc = constants.pool.escape(body.item_desc);
	var item_category = constants.pool.escape(body.item_category);
	var u_token = constants.pool.escape(body.u_token);
	//var item_photo_path = request.files.file.path;
	//console.log(item_photo_path);
	var item_photo = constants.pool.escape(body.item_photo);
	if (true) {
		var imageType = checkImageType(item_photo);
		if ((imageType == 'jpeg') || (imageType == 'jpg') || (imageType == 'png')) {
			var item_photo_name = Date.now();
			var item_photo_path = "/itemimages/" + item_photo_name + '.' + imageType;
			try {
				item_photo = item_photo.substring(item_photo.indexOf(",") + 1);
				var bufferImage = new Buffer(item_photo, 'base64');
				fs.writeFile('itemimages/' + item_photo_name + '.' + imageType, bufferImage);
			}
			catch (err) {
				imageUploadCheck = false;
			}
		}
		else {
			imageUploadCheck = false;
			response.json({
				"status": language.error_title,
				"message": language.error_filetype
			});
		}
		if (imageUploadCheck == true) {
			//Check if user exists
			var selectUserIdForNewItem = "SELECT u_id FROM users WHERE u_token = " + u_token;
			var time = moment().format('MMMM Do YYYY, h:mm:ss a');
			constants.pool.query(selectUserIdForNewItem, function(err, rows) {
				if (!err) {
					var item_ownerid = rows[0]['u_id']
					var queryForNewItem =
						"INSERT INTO items (item_id, item_name, item_desc, item_category, item_photo, item_ownerid, item_date) VALUES (" +
						0 + "," + item_name + "," + item_desc + "," + item_category + ",'" + item_photo_path + "'," + item_ownerid +
						"," + time + ")";
					constants.pool.query(queryForNewItem, function(err, result) {
						if (err) {
							response.json({
								"status": language.error_title,
								"message": language.error_database,
								"response": err
							});
						}
						else {
							response.json({
								"status": language.success_title,
								"message": language.success_newitem
							});
						}
					});
				}
				else {
					response.json({
						"status": language.error_title,
						"message": language.error_database,
						"response": err
					});
				}
			});
		}
		else {
			response.json({
				"status": language.error_title,
				"message": language.error_uploadphoto
			});
		}
	}
	else {}
}

var loginCheck = function(request, response, next) {
	try {
		var body = request.body;
		var u_name = body.u_name;
		var u_password = body.u_password;		
		console.log(u_name + " tries to login with IP " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
		var regexforusernameandpassword = /^[a-zA-Z0-9-_\u00E7\u011F\u0131\u015F\u00F6\u00FC\u00C7\u011E\u0130\u015E\u00D6\u00DC]+$/;
		var regexforemail = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
		var regextestUsername = regexforusernameandpassword.test(u_name);			
		var regextestEmail = regexforemail.test(u_name);
		var regextestPassword = regexforusernameandpassword.test(u_password);
		
// 		var queryCheckUser = "";
		if (regextestUsername || regextestEmail) {
			var queryCheckUser = "SELECT users.u_name, users.u_password, users.u_valid FROM users WHERE users.u_name = " + constants.pool.escape(u_name);
		}
		else {
			return response.json({
				"status": language.error_title,
				"message": language.error_invalidlogininput
			});
		}
		if (regextestPassword) {
			//Check if user exists
			//var queryCheckUser = "SELECT u_name, u_password FROM users WHERE u_name = " + constants.pool.escape(u_name);
			constants.pool.query(queryCheckUser, function(errCheckUser, rowsCheckUser) {
				if (!errCheckUser) {
// 					var u_namereal = "";
// 					var u_valid = "";
					var numberOfRows = rowsCheckUser.length;
					if (numberOfRows == 1) {
						var u_namereal = rowsCheckUser[0].u_name;
						var u_valid = rowsCheckUser[0].u_valid;
						if (bcrypt.compareSync(u_password, rowsCheckUser[0]['u_password'])) {}
						else {
							return response.json({
								"status": language.error_title,
								"message": language.error_invalidpassword
							});
						}
						var newToken = generateJWTToken(u_namereal, u_valid);
						newToken = encrypt(newToken, constants.ENCRYPTION_KEY_TOKEN);
						var queryUpdateUserToken = "UPDATE users SET users.u_token = '" + newToken + "' WHERE users.u_name = '" + u_namereal + "'";
						constants.pool.query(queryUpdateUserToken, function(errUpdateUserToken, rowsUpdateUserToken) {
							if (errUpdateUserToken) {
								console.log(u_name + " failed logging in with IP " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
								response.json({
									"status": language.error_title,
									"message": language.error_database,
									"response": errUpdateUserToken
								});
							}
							else {
								var encryptedpassword = encrypt(u_password, constants.ENCRYPTION_KEY_REMEMBERPASSWORD);
								var credentials = {"token": newToken, "encryptedpassword": encryptedpassword};
								console.log(u_name + " successfully logged in with IP " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
								return response.json({
									"status": language.success_title,
									"message": language.success_login,
									"response": credentials
								});
							}
						});
					}
					else if (numberOfRows < 1) {
						console.log(u_name + " failed logging in with IP " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
						return response.json({
							"status": language.error_title,
							"message": language.error_invaliduser
						});
					}
					else {
						console.log(u_name + " failed logging in with IP " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
						return response.json({
							"status": language.error_title,
							"message": language.error_login
						});
					}
				}
				else {
					console.log(u_name + " failed logging in with IP " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
					return response.json({
						"status": language.error_title,
						"message": language.error_database,
						"response": errCheckUser
					});
				}
			});
		}
		else {
			console.log(u_name + " failed logging in with IP " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
			response.json({
				"status": language.error_title,
				"message": language.error_blankpassword
			});
		}
	}
	catch (err) {
		console.log("Failed login in with IP " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
		console.log("errpr: " + err);
		return response.json({
			"status": language.error_title,
			"message": language.error_unknownerror,
			"response": err
		});
	}
}

function insertWelcomeMessage(userid, response) {
	try {
		var queryForWelcomeMessage = "INSERT INTO messages (message_id, u_id, to_uid, message_text, message_unread) VALUES (" + 0 + ", " + 1 + ", " +
			userid + ", 'Hoşgeldin, site ile ilgili soru veya sorunlarını bu alanı kullanarak bize ulaştırabilirsin.', " + 1 +")"; 
			
			constants.pool.query(queryForWelcomeMessage, function(err_queryForWelcomeMessage, result_queryForWelcomeMessage) {
				if (err_queryForWelcomeMessage) {
					return response.json({
						"status": "Uyarı",
						"message": language.error_newmessage,
						"response": err_queryForWelcomeMessage
					});
				}
			});
	}
	catch (error) {
		return response.json({
			"status": "Uyarı",
			"message": language.error_unknownerror,
			"response": error
		});
	}
}

app.get('/getallcities', function(request, response) {
	console.log("Get all cities method has been called with IP: " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
	var getAllCitiesQuery = "SELECT c_code, c_name FROM cities ORDER BY CASE WHEN c_name ='Şehir Belirtilmedi' THEN 0 ELSE 1 END, "
							+"CASE WHEN c_name ='İstanbul' THEN 0 ELSE 1 END, "
							+"CASE WHEN c_name ='İzmir' THEN 0 ELSE 1 END, "
							+"CASE WHEN c_name ='Ankara' THEN 0 ELSE 1 END, "
							+"c_name";
	constants.pool.query(getAllCitiesQuery, function(err, rows) {
		if (err) {
			console.log("Get all cities method failed by IP: " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
			return response.json({
				"status": language.error_title,
				"message": language.error_database,
				"response": err
			});
		}
		else {
			console.log("Get all cities method successfully has been returned to IP: " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
			return response.json({
				"status": language.success_title,
				"cities": rows
			});
		}
	});
});

app.post('/logout', function(request, response) {
	try {
		var body = request.body;
		var u_token = decrypt(body.u_token, constants.ENCRYPTION_KEY_TOKEN);
		//var username = body.u_name;
		
		console.log(username + " tries to login with IP " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
		
		var queryCheckUser = "SELECT u_name FROM users WHERE u_token = '" + u_token + "'";
		constants.pool.query(queryCheckUser, function(err, rows) {
			if (!err) {
				var resultLength = rows.length;
				if (resultLength > 0) {
					var tokenOwner = rows[0]['u_name'];
					var permLogoutToken = generateLogoutJWTToken();
					permLogoutToken = encrypt(permLogoutToken, constants.ENCRYPTION_KEY_TOKEN);
					var updateUserToken = constants.pool.query("UPDATE users SET u_token = '" + permLogoutToken + "'  WHERE u_name = '" +
						tokenOwner + "'",
						function(err, result) {
							if (err) {
								console.log((request.headers['x-forwarded-for'] || request.connection.remoteAddress) + " failed logging out");
								return response.json({
									"status": language.error_title,
									"message": language.error_database
								});
							}
							else {
								console.log(tokenOwner + " successfully logs out IP " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
								return response.json({
									"status": language.success_title,
									"message": tokenOwner + language.success_logout
								});
							}
						});
				}
				else {
					console.log((request.headers['x-forwarded-for'] || request.connection.remoteAddress) + " tried to logout although he/she already logged out");
					response.json({
						"status": language.error_title,
						"message": language.error_logout
					});
				}
			}
			else {
				console.log((request.headers['x-forwarded-for'] || request.connection.remoteAddress) + " failed logging out");
				return response.json({
					"status": language.error_title,
					"message": language.error_database,
					"response": err
				});
			}
		});
	}
	catch (error) {
		console.log((request.headers['x-forwarded-for'] || request.connection.remoteAddress) + " failed logging out");
		return response.json({
			"status": language.error_title,
			"message": language.error_unknownerror
		});
	}
});

app.post('/getuser', function (request, response) {
	function getUser(request, response, queryGetUser){
		constants.pool.query(queryGetUser, function(errGetUser, rowsGetUser) {
			if (errGetUser) {
				response.json({
					"status": language.error_title,
					"message": language.error_database,
					"response": errGetUser
				});
			}
			else {
				try {
					var resultLength = rowsGetUser.length;
					if (!resultLength) {
						return response.json({
							"status": language.error_title,
							"message": language.error_invaliduser
						});
					}
					else {
						var responseobject = {};
						var currentrow = rowsGetUser[resultLength - 1];
						var user = new classes.User(selected_id, currentrow.u_name, currentrow.u_photo, currentrow.c_name, currentrow.c_code, null, null, null, null, currentrow.u_info, currentrow.u_notificationforbids, currentrow.u_notificationformessages);
						if (currentrow.relation_type == 'Block'){
							user["blocked"] = true;
						}
						var items = [];
						for (var i = 0; i < resultLength - 1; i++) {
							currentrow = rowsGetUser[i];
							if (currentrow.item_deleted == 0) {
								var item_owner = new classes.User(currentrow.item_ownerid, currentrow.u_name, currentrow.u_photo, currentrow.c_name, currentrow.c_code, null, null, null, null, currentrow.u_info);
								var item = new classes.Item(currentrow.item_id, currentrow.item_name, currentrow.item_desc, currentrow.item_category, null, currentrow.item_photo, currentrow.item_date, item_owner);
								items.push(item);
							}
						}
						responseobject["user"] = user;
						responseobject["items"] = items;
						return response.json({
							"status": language.success_title,
							"response": responseobject
						});
					}
				}
				catch (error) {
					response.json({
						"status": language.error_title,
						"message": language.error_userinput
					});
				}
			}
		});
	}
	try {
		var body = request.body;
		var selected_id = body.selected_id;
		if (selected_id == null) {
			return response.json({
				"status": language.error_title,
				"message": language.error_invaliduser
			});
		}
		var u_token = body.u_token;
		if (null != u_token) {
			authentication(request, response, function(){
				var userid = body.u_id;		
				var queryGetUser =
				"SELECT * FROM ( "
				+"SELECT users.u_name, users.u_photo, users.u_info, users.u_notificationforbids, users.u_notificationformessages, NULL as item_id, NULL as item_name, NULL as item_desc, NULL as item_category, NULL as item_photo, NULL as item_ownerid, NULL as item_date, cities.c_name, cities.c_code, NULL as item_deleted, user_relations.relation_type "
				+"FROM users "
				+"JOIN cities ON (cities.c_code = users.u_location) "
				+"LEFT JOIN user_relations ON user_relations.relation_deleted = '0' AND (user_relations.user_id = " + userid + " AND users.u_id = user_relations.related_user_id) "
				+"WHERE users.u_id = " + selected_id + " UNION ALL "
				+"SELECT users.u_name, users.u_photo, users.u_info, users.u_notificationforbids, users.u_notificationformessages, items.`item_id`, items.item_name, items.item_desc, items.item_category, items.item_photo, items.item_ownerid, items.item_date, cities.c_name, cities.c_code, items.item_deleted, user_relations.relation_type "
				+"FROM users "
				+"JOIN cities ON (cities.c_code = users.u_location) "
				+"JOIN items ON (items.item_ownerid = users.u_id) "
				+"LEFT JOIN user_relations ON user_relations.relation_deleted = '0' AND (user_relations.user_id = " + userid + " AND users.u_id = user_relations.related_user_id) "				
				+"WHERE users.u_id = " + selected_id
				+") getuserresult "
				+"ORDER BY getuserresult.item_date DESC";
				getUser(request, response, queryGetUser);
			});
		}
		else{
			var queryGetUser =
			"SELECT * FROM ( "			
			+"SELECT users.u_name, users.u_photo, users.u_info, users.u_notificationforbids, users.u_notificationformessages, NULL as item_id, NULL as item_name, NULL as item_desc, NULL as item_category, NULL as item_photo, NULL as item_ownerid, NULL as item_date, cities.c_name, cities.c_code, NULL as item_deleted "
			+"FROM users "
			+"JOIN cities ON (cities.c_code = users.u_location) "
			+"WHERE users.u_id = " + selected_id + " UNION ALL "
			+"SELECT users.u_name, users.u_photo, users.u_info, users.u_notificationforbids, users.u_notificationformessages, items.`item_id`, items.item_name, items.item_desc, items.item_category, items.item_photo, items.item_ownerid, items.item_date, cities.c_name, cities.c_code, items.item_deleted "
			+"FROM users "
			+"JOIN cities ON (cities.c_code = users.u_location) "
			+"JOIN items ON (items.item_ownerid = users.u_id) "
			+"WHERE users.u_id = " + selected_id
			+") getuserresult "
			+"ORDER BY getuserresult.item_date DESC";
			getUser(request, response, queryGetUser);
		}
	}
	catch (error) {
		response.json({
			"status": language.error_title,
			"message": language.error_unknownerror,
			"response": JSON.stringify(error)
		});
	}
});

app.get('/getitem/:itemid', function(request, response) {
	try {
		var item_id = constants.pool.escape(request.params.itemid);
		if (item_id == null) {
			return response.json({
				"status": language.error_title,
				"message": language.error_invaliditem
			});
		}
		var getItemInfoQuery =
			"SELECT items.item_name, items.item_desc, items.item_category, item_photo, items.item_date, users.u_name, users.u_id, users.u_photo, users.u_info, cities.c_name, categories.category_name "
			+"FROM items "
			+"JOIN users ON (items.item_ownerid = users.u_id) "
			+"JOIN cities ON (users.u_location = cities.c_code) "
			+"JOIN categories ON (categories.category_id = items.item_category) "
			+"WHERE items.item_id = " + item_id + " AND items.item_deleted = 0";
		constants.pool.query(getItemInfoQuery, function(err, rows) {
			if (err) {
				response.json({
					"status": language.error_title,
					"message": language.error_database
				});
			}
			else {
				try {
					var resultLength = rows.length;
					if (resultLength < 1) {
						return response.json({
							"status": language.error_title,
							"message": language.error_itemnotfound
						});
					}
					else if (resultLength == 1) {
						var currentrow = rows[0];
						var item_owner = new classes.User(currentrow.u_id, currentrow.u_name, currentrow.u_photo, currentrow.c_name, currentrow.c_code, null, null, null, null, currentrow.u_info);
						var item = new classes.Item(item_id, currentrow.item_name, currentrow.item_desc, currentrow.item_category, currentrow.category_name, currentrow.item_photo, currentrow.item_date, item_owner);
						return response.json({
							"status": language.success_title,
							"item": item
						});
					}
					else {
						return response.json({
							"status": language.error_title,
							"message": language.error_multipleitemfound
						});
					}
				}
				catch (error) {
					response.json({
						"status": language.error_title,
						"message": language.error_userinput
					});
				}
			}
		});
	}
	catch (error) {
		response.json({
			"status": language.error_title,
			"message": language.error_unknownerror
		});
	}
});

app.post('/signup', function(request, response) {
	try {
		var body = request.body;
		var u_name = body.u_name;
		var u_password =  bcrypt.hashSync(body.u_password, 10);
		var u_email = body.u_email;
		var u_token = encrypt(generateJWTToken(u_name, 0), constants.ENCRYPTION_KEY_TOKEN);
				
		var regexforusernameandpassword = /^[a-zA-Z0-9-_\u00E7\u011F\u0131\u015F\u00F6\u00FC\u00C7\u011E\u0130\u015E\u00D6\u00DC]+$/;
		var regextestUsername = regexforusernameandpassword.test(body.u_name);
		var regextestPassword = regexforusernameandpassword.test(body.u_password);
		var regexforemail = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
		var regextestEmail = regexforemail.test(body.u_email);		

		if (regextestUsername && regextestPassword && regextestEmail) {
			//Check if username or email exists
			var queryCheckUser = "SELECT COUNT(*) as total, u_valid FROM users WHERE users.u_name =  " + constants.pool.escape(u_name) + " OR users.u_email = " + constants.pool.escape(u_email);
			constants.pool.query(queryCheckUser, function(errCheckUser, rowsCheckUser) {
				if (!errCheckUser) {
					var numberOfRows = rowsCheckUser[0].total;				
					if (numberOfRows <= 0) {
						if (request.body['recaptcha'] === null || request.body['recaptcha'] === '') {
							return response.json({
								"status": language.error_title,
								"message": language.error_recaptcha
							});
						}
						// request.connection.remoteAddress will provide IP address of connected user.
						var verificationUrl = "https://www.google.com/recaptcha/api/siteverify?secret=" + constants.SECRET_KEY + "&response=" + request.body['recaptcha'] + "&remoteip=" + request.connection.remoteAddress;
						// Hitting GET request to the URL, Google will respond with success or error scenario.
						requestC(verificationUrl, function(errorRecaptcha, responseRecaptcha, body) {
							body = JSON.parse(body);
							// Success will be true or false depending upon captcha validation.
							if (body.success !== null && !body.success) {
								return response.json({
									"status": language.error_title,
									"message": language.error_recaptcha,
									"response": errorRecaptcha
								});
							}
							else{
								// setup email data with unicode symbols
								var mailOptions = {
									from: '"Swaplat" <support@swaplat.com>', // sender address
									to: u_email, // list of receivers
									subject: 'Üyeliğinizi onaylayın', // Subject line
									html: 'Merhaba '+ u_name +', '
										+'<p>Aşağıdaki butona tıklayarak Swaplat üyeliğini onaylayıp aktifleştirebilirsin. </p> '
										+'<a href="https://swaplat.com/validateuser.php?token='+ u_token +'"> <span style="display: inline-block; font-size: 16px; padding: 10px 18px; color: #fff; background-color: #427951; vertical-align: middle; font-weight: bold; text-decoration: none; border: 1px solid #EFF2EB; border-radius: 4px;">Onayla</span></a>'
								};
								// send mail with defined transport object
								constants.transporter.sendMail(mailOptions, (errorMail, info) => {
									if (errorMail) {
										console.log("Failed to create a new user with username " + u_name + " using IP " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));									
										return response.json({
											"status": language.error_title,
											"message": language.error_email,
											"response": errorMail
										});
									}
									else {
										var queryCreateUser = 
											"INSERT INTO users (u_id, u_name, u_password, u_email, u_token, u_photo) "
											+"VALUES (" + 0 + "," + constants.pool.escape(u_name) + "," + constants.pool.escape(u_password) + "," + constants.pool.escape(u_email) + "," + constants.pool.escape(u_token) + ", "+constants.pool.escape(constants.CLOUDINARY_ANON_USER_PHOTO)+")";								
										constants.pool.query(queryCreateUser, function(errCreateUser, rowsCreateUser) {
											if (errCreateUser) {
											console.log("Failed to create a new user with username " + u_name + " using IP " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));											
												return response.json({
													"status": language.error_title,
													"message": language.error_database,
													"response": errCreateUser
												});
											}
											else {																										
												return response.json({
													"status": language.success_title,
													"message": language.success_newuser
												});
											}
										});
									}
								});
							}
						});
					}
					else {
						console.log("Failed to create a new user with username " + u_name + " using IP " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
						return response.json({
							"status": language.error_title,
							"message": language.error_invalidsignup,
							"response": errCheckUser
						});
					}
				}
				else {
					console.log("Failed to create a new user with username " + u_name + " using IP " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
					return response.json({
						"status": language.error_title,
						"message": language.error_database,
						"response": errCheckUser
					});
				}
			});
		}
		else {
			if (regextestUsername == false) {
				console.log("Failed to create a new user with username " + u_name + " using IP " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
				return response.json({
					"status": language.error_title,
					"message": language.error_invalidsignupusername
				});
			}
			else if (regextestPassword == false) {
				console.log("Failed to create a new user with username " + u_name + " using IP " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
				return response.json({
					"status": language.error_title,
					"message": language.error_invalidsignuppassword
				});
			}
			else if (regextestEmail == false) {
				console.log("Failed to create a new user with username " + u_name + " using IP " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
				return response.json({
					"status": language.error_title,
					"message": language.error_email
				});
			}
			else {
				return response.json({
					"status": language.error_title,
					"message": language.error_invalidsignupinput
				});
			}
		}
	}
	catch (error) {
		return response.json({
			"status": language.error_title,
			"message": language.error_unknownerror,
			"response": error
		});
	}
});

app.post('/getusernameandpassword', function(request, response) {
	try {
		var body = request.body;
		var u_token = body.u_token;
		var u_encryptedpassword = body.u_encryptedpassword;
		var decu_token = decrypt(u_token, constants.ENCRYPTION_KEY_TOKEN);
		jwt.verify(decu_token, process.env.JWTTOKEN_KEY, function(errorVerifiyToken, responseVerifyToken) {
			if (errorVerifiyToken) { //failed verification.
				return response.json({
					"status": language.error_title,
					"message": language.error_invalidtoken
				});
			}
			var u_name = responseVerifyToken.username;
			var u_decryptedpassword = decrypt(u_encryptedpassword, constants.ENCRYPTION_KEY_REMEMBERPASSWORD);
			var credentials = {"u_name": u_name, "u_decryptedpassword": u_decryptedpassword};
			return response.json({
				"status": language.success_title,
				"response": credentials
			});						
		});	
	}
	catch (error) {
		return response.json({
			"status": language.error_title,
			"message": language.error_unknownerror,
			"response": error
		});
	}
});

app.post('/authenticate', authentication, function(request, response) {
	try {
		var body = request.body;
		var u_id = body.u_id;
		var u_name = body.username;
		var u_photo = body.u_photo;
		var u_unreadmessage = body.u_unreadmessage;
		var u_unreadbids = body.u_unreadbids;
		var user = new classes.User(u_id, u_name, u_photo, null, null, u_unreadmessage, null, u_unreadbids);
		console.log(u_name + " has called authentication function with " + (request.headers['x-forwarded-for'] || request.connection
			.remoteAddress));
		return response.json({
			"status": language.success_title,
			"User": user
		});
	}
	catch (error) {
		console.log("An nexpected error occured when " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress) +
			" tried to call authentication function!");
		return response.json({
			"status": language.error_title,
			"message": language.error_unknownerror
		});
	}
});

app.use('/login', constants.limiter);
app.post('/login', loginCheck, function(request, response) {});
app.get('/', function(request, response) {
	response.redirect('https://swaplat.com');
});

app.post('/newitem', authentication, function(request, response) {
	if (request.body.message == language.error_title) {
		response.json(request.body.status);
	}
	else {
		insertNewItem(request, response);
	}
});
app.post('/forgotpassword', function(request, response) {
	try {
		var body = request.body;
		var u_email = body.u_email;
		console.log(u_email + " tries to reset password with IP " + (request.headers['x-forwarded-for'] || request.connection
			.remoteAddress));
		var queryCheckUser = "SELECT u_id, u_name, u_valid FROM users WHERE u_email = " + constants.pool.escape(u_email);
		constants.pool.query(queryCheckUser, function(err, rows) {
			if (!err) {
				var resultLength = rows.length;
				if (resultLength == 1) {
					var userId = rows[0]['u_id'];
					var tokenOwner = rows[0]['u_name'];
					var u_valid = rows[0]['u_valid'];
					var forgottenToken = generateJWTTokenForForgottenPassword(tokenOwner, u_valid);
					var encForgottenToken = encrypt(forgottenToken, constants.ENCRYPTION_KEY_FORGOTPASSWORD);
					var checkifuserforgotpassword = "SELECT requ_id FROM newpass_requests WHERE requ_id = " + constants.pool.escape(userId);
					constants.pool.query(checkifuserforgotpassword, function(err, rows2) {
						if (!err) {
							var resultLength2 = rows2.length;
							if (resultLength2 == 0) {
								var forgottenPasswordTokenReq = "INSERT INTO newpass_requests (requ_id, forgot_utoken) VALUES (" + userId +",'" + encForgottenToken + "')";
								constants.pool.query(forgottenPasswordTokenReq, function(err, rows2) {
									if (!err) {
										// setup email data with unicode symbols
										var mailOptions = {
											from: '"Swaplat" <support@swaplat.com>', // sender address
											to: u_email, // list of receivers
											subject: 'Swaplat şifre yenileme', // Subject line
											html: 'Merhaba '+tokenOwner+', '
											+'<p>Aşağıdaki linke tıklayarak Swaplat şifreni değiştirebilirsin: </p> '
											+'<a href="https://swaplat.com/resetpassword.php?token=' + encForgottenToken + '"> '
											+'<span style="display: inline-block; font-size: 16px; padding: 10px 18px; color: #fff; background-color: #427951; vertical-align: middle; font-weight: bold; line-height: 18px; text-decoration: none; border: 1px solid #EFF2EB; border-radius: 4px;">Değiştir'
											+'</span>'
											+'</a>'
										};
										// send mail with defined transport object
										constants.transporter.sendMail(mailOptions, (error, info) => {
											if (error) {
												console.log("Email could not be sent to " + u_email + " because of the error: " + error);
												return response.json({
													"status": language.error_title,
													"message": language.error_email
												});
											}
											else {
												console.log("An e-mail has been sent to " + u_email + " with password reset instructions");
												return response.json({
													"status": language.success_title,
													"message": language.success_email
												});
											}
										});
									}
									else {
										return response.json({
											"status": language.error_title,
											"message": language.error_database
										});
									}
								});
							}
							else if (resultLength2 == 1) {
								var updateForgotPassToken = constants.pool.query("UPDATE newpass_requests SET forgot_utoken = '" +
									encForgottenToken + "' WHERE requ_id = '" + userId + "'",
									function(err, result) {
										if (err) {
											//response.json({ "status": language.error_title, "message" : language.error_database});
											return response.json({
												"status": language.error_title,
												"message": language.error_database
											});
										}
										else {
											var mailOptions = {
												from: '"Swaplat" <support@swaplat.com>', // sender address
												to: u_email, // list of receivers
												subject: 'Swaplat şifre yenileme', // Subject line
												html: 'Merhaba '+tokenOwner+', '
												+'<p>Aşağıdaki linke tıklayarak Swaplat şifreni değiştirebilirsin: </p> '
												+'<a href="https://swaplat.com/resetpassword.php?token=' + encForgottenToken + '"> '
												+'<span style="display: inline-block; font-size: 16px; padding: 10px 18px; color: #fff; background-color: #427951; vertical-align: middle; font-weight: bold; line-height: 18px; text-decoration: none; border: 1px solid #EFF2EB; border-radius: 4px;">Değiştir'
												+'</span>'
												+'</a>'											
											};
											// send mail with defined transport object
											constants.transporter.sendMail(mailOptions, (error, info) => {
												if (error) {
													console.log("Email could not be sent to " + u_email + " because of the error: " + error);
													return console.log("An e-mail has been sent to " + u_email + " with password reset instructions");
												}
												else {
													console.log("An e-mail has been sent to " + u_email + " with password reset instructions");
													return response.json({
														"status": language.success_title,
														"message": language.success_email
													});
												}
											});
										}
									});
							}
							else {
								console.log(tokenOwner + " failed reset his/her password");
								return response.json({
									"status": language.error_title,
									"message": language.error_resetpassword
								});
							}
						}
						else {
							console.log(tokenOwner + " failed reset his/her password");
							return response.json({
								"status": language.error_title,
								"message": language.error_database
							});
						}
					});
				}
				else {
					console.log(tokenOwner + " failed reset his/her password");
					return response.json({
						"status": language.error_title,
						"message": language.error_resetpassword
					});
				}
			}
			else {
				console.log(tokenOwner + " failed reset his/her password");
				return response.json({
					"status": language.error_title,
					"message": language.error_database
				});
			}
		});
	}
	catch (err2) {
		return response.json({
			"status": language.error_title,
			"message": language.error_unknownerror
		});
	}
});
app.post('/validateuser', function(request, response) {
	try {
		var body = request.body;
		var u_token = body.u_token;
		var decu_token = decrypt(u_token, constants.ENCRYPTION_KEY_TOKEN);
		jwt.verify(decu_token, process.env.JWTTOKEN_KEY, function(err, decoded) {
			if (err) { //failed verification.
				return response.json({
					"status": language.error_title,
					"message": language.error_invalidtoken
				});
			}
			//console.log(decoded);
			var u_name = decoded.username;
			console.log(u_name + " tries to validate his/her account with IP " + (request.headers['x-forwarded-for'] ||
				request.connection.remoteAddress));
			var validationQuery = "SELECT u_id, u_name FROM users WHERE u_name = " + constants.pool.escape(u_name);
			constants.pool.query(validationQuery, function(err, rows) {
				if (!err) {
					var resultLength = rows.length;
					if (resultLength == 1) {
						var userId = rows[0]['u_id'];
						var tokenOwner = rows[0]['u_name'];
						//var u_valid= rows[0]['u_valid'];
						var validateuser = "UPDATE users SET u_valid = 1 WHERE u_name = '" + tokenOwner + "'";
						constants.pool.query(validateuser, function(err, rows2) {
							if (!err) {
								var validationToken = generateJWTToken(tokenOwner, 1);
								var encValidationToken = encrypt(validationToken, constants.ENCRYPTION_KEY_TOKEN);
								var updatetokenQuery = "UPDATE users SET u_token = '" + encValidationToken + "' WHERE u_name = '" +
									tokenOwner + "'";
								constants.pool.query(updatetokenQuery, function(err, rows2) {
									if (!err) {
										console.log(u_name + " successfully validated his/her account with IP " + (request.headers[
											'x-forwarded-for'] || request.connection.remoteAddress) + " and logging in");
										insertWelcomeMessage(userId, response);

										return response.json({
											"status": language.success_title,
											"message": language.success_login,
											"token": encValidationToken
										});
									}
									else {
										console.log(u_name + " successfully validated his/her account with IP " + (request.headers[
											'x-forwarded-for'] || request.connection.remoteAddress));
										return response.json({
											"status": language.success_title,
											"message": language.error_relogin
										});
									}
								});
							}
							else {
								console.log((request.headers['x-forwarded-for'] || request.connection.remoteAddress) + " failed validating his/her account with IP");
								return response.json({
									"status": language.error_title,
									"message": language.error_database
								});
							}
						});
					}
					else {
						console.log((request.headers['x-forwarded-for'] || request.connection.remoteAddress) + " failed validating his/her account with IP");
						return response.json({
							"status": language.error_title,
							"message": language.error_login
						});
					}
				}
				else {
					console.log((request.headers['x-forwarded-for'] || request.connection.remoteAddress) + " failed validating his/her account with IP");
					return response.json({
						"status": language.error_title,
						"message": language.error_database
					});
				}
			});
		});
	}
	catch (error) {
		console.log((request.headers['x-forwarded-for'] || request.connection.remoteAddress) + " failed validating his/her account with IP");
		return response.json({
			"status": language.error_title,
			"message": language.error_unknownerror
		});
	}
});
app.post('/setnewpassword/', function(request, response) {
	try {
		console.log("Set New Pass called with IP " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
		var u_password = request.body.u_password;
		var emptyTest = /^[a-zA-Z0-9-_]+$/.test(u_password);
		if (emptyTest !== true) {
			return response.json({
				"status": language.error_title,
				"message": language.error_invalidsignuppassword
			});
		}
		var token = request.body.resettoken;
		if (token == null || token == undefined) {
			return response.json({
				"status": language.error_title,
				"message": language.error_tokennotreached
			});
		}
		var checkifuserforgotpasswordexist = "SELECT requ_id FROM newpass_requests WHERE forgot_utoken = " + constants.pool.escape(token);
		constants.pool.query(checkifuserforgotpasswordexist, function(err, rows2) {
			if (err) {
				console.log((request.headers['x-forwarded-for'] || request.connection.remoteAddress) + " failed setting a new password with IP");
				return response.json({
					"status": language.error_title,
					"message": language.error_unknownerror
				});
			}
			else {
				if (rows2.length == 0) {
					console.log((request.headers['x-forwarded-for'] || request.connection.remoteAddress) + " failed setting a new password with IP");
					return response.json({
						"status": language.error_title,
						"message": language.error_sametoken
					});
				}
				else {
					var decryptedToken = decrypt(token, constants.ENCRYPTION_KEY_FORGOTPASSWORD);
					if (decryptedToken == "response") {
						console.log((request.headers['x-forwarded-for'] || request.connection.remoteAddress) + " failed setting a new password with IP");
						return response.json({
							"status": language.error_title,
							"message": language.error_decryption
						});
					}
					jwt.verify(decryptedToken, process.env.JWTTOKENFORFORGOTTONPASSWORD_KEY, function(err, decoded) {
						if (err) { //failed verification.
							console.log((request.headers['x-forwarded-for'] || request.connection.remoteAddress) + " failed setting a new password with IP");
							return response.json({
								"status": language.error_title,
								"message": language.error_invalidtoken
							});
						}
						var expdate = decoded.expiresIn;
						var iat = decoded.iat;
						var u_name = decoded.username;
						u_password = bcrypt.hashSync(u_password, 10);
						var verifySetNewPassword = constants.pool.query("UPDATE users SET u_password = '" + u_password +
							"'  WHERE u_name = '" + u_name + "'",
							function(err, result) {
								if (err) {
									console.log((request.headers['x-forwarded-for'] || request.connection.remoteAddress) + " failed setting a new password with IP");
									response.json({
										"status": language.error_title,
										"message": language.error_database
									});
								}
								else {
									try {
										var deleteOldresettoken = "DELETE FROM newpass_requests WHERE forgot_utoken = '" + token + "'";
										constants.pool.query(deleteOldresettoken, function(err, rows) {
											if (err) {
												console.log((request.headers['x-forwarded-for'] || request.connection.remoteAddress) + " failed setting a new password with IP");
												return response.json({
													"status": language.error_title,
													"message": language.error_database,
													"response": err
												});
											}
											else {
												console.log(u_name + " successfully set a new password with IP: "+ (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
												return response.json({
													"status": language.success_title,
													"message": language.success_newpassword
												});
											}
										});
									}
									catch (error) {
										console.log(u_name + " successfully set a new password with IP: "+ (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
										return response.json({
											"status": language.success_title,
											"message": language.success_newpassword
										});
									}
								}
							});
					});
				}
			}
		});
	}
	catch (error) {
		console.log((request.headers['x-forwarded-for'] || request.connection.remoteAddress) + " failed setting a new password with IP");
		return response.json({
			"status": language.error_title,
			"message": language.error_unknownerror
		});
	}
});

app.post('/getallitems', function(request, response) {
	function callGetAllItemsQuery(request, response, querySelectAllItems){
		constants.pool.query(querySelectAllItems, function(err, rows) {
			if (!err) {
				var items = [];
				var resultLength = rows.length;
				for (var i = 0; i < resultLength; i++) {
					var currentrow = rows[i];
					var item_owner = new classes.User(currentrow.item_ownerid, currentrow.u_name, currentrow.u_photo, currentrow.c_name, currentrow.c_code);
					var item = new classes.Item(currentrow.item_id, currentrow.item_name, currentrow.item_desc, currentrow.item_category, null, currentrow.item_photo, currentrow.item_date, item_owner);
					items.push(item);
				}
				console.log("All items have been returned successfully to IP " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
				return response.json({
					"status": language.success_title,
					"response": items
				});
			}
			else {
				console.log("Items failed to return.");				
				return response.json({
					"status": language.error_title,
					"message": language.error_getallitems,
					"response": err
				});
			}
		});
	}
	try {
		console.log("getallitemsprivate function has been called by IP " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
		var body = request.body;
		var u_token = body.u_token;
		if (null != u_token) {
			authentication(request, response, function(){		
				var user_id = constants.pool.escape(body.u_id);
				if (null == user_id) {
					return response.json({
						"status": language.error_title,
						"message": language.error_invaliduser
					});
				}
				var querySelectAllItems =
				"SELECT users.u_name, users.u_photo, items.item_id, items.item_name, items.item_desc, items.item_category, items.item_photo, items.item_ownerid, items.item_date, cities.c_name, cities.c_code "
				+"FROM items "
				+"JOIN users ON (items.item_ownerid = users.u_id) "
				+"JOIN cities ON (cities.c_code = users.u_location) "
				+"LEfT JOIN user_relations ON user_relations.relation_type = 'Block' AND user_relations.relation_deleted = '0' AND ((user_relations.user_id = "+ user_id +" AND users.u_id = user_relations.related_user_id) OR (user_relations.related_user_id = "+ user_id +" AND users.u_id = user_relations.user_id)) "
				+"WHERE items.item_deleted = 0 AND user_relations.related_user_id IS NULL "
				+"ORDER BY items.item_date DESC";
				callGetAllItemsQuery(request, response, querySelectAllItems);
			});
		}
		else{
			var querySelectAllItems =
			"SELECT users.u_name, users.u_photo, items.item_id, items.item_name, items.item_desc, items.item_category, items.item_photo, items.item_ownerid, items.item_date, cities.c_name, cities.c_code "
			+"FROM items "
			+"JOIN users ON (items.item_ownerid = users.u_id) "
			+"JOIN cities ON (cities.c_code = users.u_location) "			
			+"WHERE item_deleted = 0 "
			+"ORDER BY items.item_date DESC";
			callGetAllItemsQuery(request, response, querySelectAllItems);			
		}
	}
	catch (error) {
		console.log("Items failed to return." + "ERROR: " + error);				
		return response.json({
			"status": language.error_title,
			"message": language.error_unknownerror
		});
	}
});

app.post('/getbidbyid', authentication, function(request, response) {
	try {
		var body = request.body;
		var userid = body.u_id;
		var bid_id = body.bid_id;
		var username = body.username;
		var u_token = body.u_token;
		console.log(username + " tries to get bid with id number: " + bid_id);
		if (null == bid_id) {
			return response.json({
				"status": language.error_title,
				"message": language.error_invaliduser
			});
		}
		else {
			var queryCheckAuthentication = 
			"SELECT users.u_token FROM users JOIN bids ON (bids.bid_id = "+ bid_id +") AND (bids.receiver_id = users.u_id) "
			+"UNION "
			+"SELECT users.u_token FROM users JOIN bids ON (bids.bid_id = "+ bid_id +") AND (bids.bidder_id = users.u_id)";
			console.log("queryCheckAuthentication: " + queryCheckAuthentication);
			constants.pool.query(queryCheckAuthentication, function(errCheckAuthentication, rowsCheckAuthentication) {
				if (errCheckAuthentication) {
					return response.json({
						"status": language.error_title,
						"message": language.error_database,
						"response": errCheckAuthentication
					});
				}
				else{
					var receiver_token = rowsCheckAuthentication[0].u_token;
					var bidder_token = rowsCheckAuthentication[1].u_token;
					console.log("bidder_token: " + bidder_token);
					if(u_token != receiver_token && u_token != bidder_token){
						return response.json({
							"status": language.error_title,
							"message": language.error_authorization
						});
					}
					else{
						var querySelectBidById =
							 "SELECT bids.accepted_by_bidder, bids.accepted_by_receiver, items.item_id, items.item_name, items.item_desc, items.item_photo, items.item_category, users.u_id, users.u_name, users.u_photo, cities.c_name, bids.bidder_bidunread, bids.receiver_bidunread "
							+"FROM bids "
							+"JOIN items ON (items.item_id = bids.toitem_id) AND (items.item_deleted = 0 OR (items.item_deleted = 1 AND bids.accepted_by_receiver <> 0)) "
							+"JOIN users ON (bids.receiver_id = users.u_id) "
							+"JOIN cities ON (cities.c_code = users.u_location) "
							+"WHERE bids.bid_id = "+ bid_id +" "
							+"UNION "
							+"SELECT bids.accepted_by_bidder, bids.accepted_by_receiver, items.item_id, items.item_name, items.item_desc, items.item_photo, items.item_category, users.u_id, users.u_name, users.u_photo, cities.c_name, bids.bidder_bidunread, bids.receiver_bidunread "
							+"FROM bids "
							+"JOIN items ON (items.item_deleted = 0 OR (items.item_deleted = 1 AND bids.accepted_by_receiver <> 0)) "
							+"JOIN item_bids_relation ON (items.item_id = item_bids_relation.bids_itemid) AND (item_bids_relation.bid_id = "+ bid_id +") "
							+"JOIN users ON (bids.bidder_id = users.u_id) "
							+"JOIN cities ON (cities.c_code = users.u_location) "
							+"WHERE bids.bid_id = " + bid_id;
						constants.pool.query(querySelectBidById, function(err, rows) {
							if (err) {
								return response.json({
									"status": language.error_title,
									"message": language.error_bid
								});
							}
							else {
								if (rows.length == 0) {
									return response.json({
										"status": language.error_title,
										"message": language.error_invalidbid
									});
								}
								else {
									var receiver_id, receiver_name, receiver_photo, receiver_location;
									var bidder_id, bidder_name, bidder_photo, bidder_location;						
									var bid_status, bidder_bidunread, receiver_bidunread;
									var received_items = [];
									var offered_items = [];
									for (var i = 0; i < rows.length; i++) {
										var currentrow = rows[i];
										var currentowner = new classes.User(currentrow.u_id, currentrow.u_name, currentrow.u_photo, currentrow.c_name);
										var currentitem = new classes.Item(currentrow.item_id, currentrow.item_name, currentrow.item_desc, 
											currentrow.item_category, null, currentrow.item_photo, null, currentowner)
										if (i == 0) {
											receiver_id = currentrow.u_id;
											receiver_name = currentrow.u_name;
											receiver_photo = currentrow.u_photo;
											receiver_location = currentrow.c_name;
											received_items.push(currentitem);
								
											bid_status = currentrow.accepted_by_receiver;
											bidder_bidunread = currentrow.bidder_bidunread;
											receiver_bidunread = currentrow.receiver_bidunread;
										}
										else {
											bidder_id = currentrow.u_id;
											bidder_name = currentrow.u_name;
											bidder_photo = currentrow.u_photo;
											bidder_location = currentrow.c_name;								
											offered_items.push(currentitem);
										}
									}
									var receiver = new classes.User(receiver_id, receiver_name, receiver_photo, receiver_location);
									var bidder = new classes.User(bidder_id, bidder_name, bidder_photo, bidder_location);
									var bid = new classes.Bid(bid_id, bidder, receiver, offered_items, received_items, bid_status);
								}
								if ((bidder_id == userid && bidder_bidunread == 1) || (receiver_id == userid && receiver_bidunread == 1)) {
									var queryMakeBidRead;
									if(bidder_id == userid){
										queryMakeBidRead = "UPDATE bids SET bidder_bidunread = 0 WHERE bidder_id = " + userid + " AND bid_id = " + bid_id;
									}
									else if(receiver_id == userid){
										queryMakeBidRead = "UPDATE bids SET receiver_bidunread = 0 WHERE receiver_id = " + userid + " AND bid_id = " + bid_id;
									}
									constants.pool.query(queryMakeBidRead, function(err, rows) {
										if (err) {
											return response.json({
												"status": language.error_title,
												"message": language.error_database
											});
										}
										else {
											console.log(username + " updated queryMakeBidRead by IP: " + (request.headers['x-forwarded-for'] ||
												request.connection.remoteAddress));
										}
									});
								}
								console.log(username + " successfully gets the bid by id number: " + bid_id + " by IP : " + (request.headers[
									'x-forwarded-for'] || request.connection.remoteAddress));
								return response.json({
									"status": language.success_title,
									"response": bid
								});
							}
						});
					}
				}
			});
		}
	}
	catch (error) {
		console.log((request.headers['x-forwarded-for'] || request.connection.remoteAddress) + " failed getting the bid by id number: " + bid_id);
		return response.json({
			"status": language.error_title,
			"message": language.error_unknownerror
		});
	}
});
app.post('/getbidsofuser', authentication, function(request, response) {
	try {
		var body = request.body;
		var user_id = body.u_id;
		var username = body.username;
		console.log(username + " tries to get his/her message list by IP : " + (request.headers['x-forwarded-for'] || request
			.connection.remoteAddress));
		if (user_id == null) {
			return response.json({
				"status": language.error_title,
				"message": language.error_invaliduser
			});
		}
		else {
			var querySelectAllBidsOfUser =
				"SELECT bid_id, bidder_bidunread, receiver_bidunread, accepted_by_bidder, accepted_by_receiver, receiver_id, bidder_id, u_name, u_photo, toitem_name, toitem_id, toitem_photo, itemdeleted, bids_itemid as optionitemid, item_name as withitem_name, item_photo as withitem_photo "
				+"FROM (SELECT DISTINCT bidid, bidder_bidunread, receiver_bidunread, accepted_by_bidder, accepted_by_receiver, receiver_id, bidder_id, u_name, u_photo, item_name as toitem_name, toitem_id, toitem_photo, item_deleted as itemdeleted, bid_id, bids_itemid "
				+"FROM (SELECT bid_id as bidid, bidder_bidunread, receiver_bidunread, accepted_by_bidder, accepted_by_receiver, receiver_id, bidder_id, u_name, u_photo, item_name, item_id as toitem_id, item_name as toitem_name, item_photo as toitem_photo, item_deleted "
				+"FROM "
					+"(SELECT DISTINCT bids.bid_id, bids.bidder_bidunread, bids.receiver_bidunread, bids.accepted_by_bidder, bids.accepted_by_receiver, bids.receiver_id, bids.bidder_id, bids.toitem_id as toitemid, users.u_name, users.u_photo, items.item_name as with_itemname, items.item_photo as with_itemphoto "
					+"FROM bids "
					+"JOIN users ON (bids.bidder_id = users.u_id) "
					+"JOIN item_bids_relation ON (item_bids_relation.bid_id = bids.bid_id) "
					+"JOIN items ON (item_bids_relation.bids_itemid = items.item_id) "
					+"LEFT JOIN user_relations ON user_relations.relation_type = 'Block' AND user_relations.relation_deleted = '0' AND ((user_relations.user_id = " + user_id + " AND bids.bidder_id = user_relations.related_user_id) OR (user_relations.related_user_id = " + user_id + " AND bids.bidder_id = user_relations.user_id)) "
					+"WHERE bids.receiver_id = " + user_id + " AND user_relations.related_user_id IS NULL "
					+"UNION ALL "
					+ "SELECT DISTINCT bids.bid_id, bids.bidder_bidunread, bids.receiver_bidunread, bids.accepted_by_bidder, bids.accepted_by_receiver, bids.receiver_id, bids.bidder_id, bids.toitem_id as toitemid, users.u_name, users.u_photo, items.item_name as with_itemname, items.item_photo as with_itemphoto "
					+"FROM bids "
					+"JOIN users ON (bids.receiver_id = users.u_id) "
					+"JOIN item_bids_relation ON (item_bids_relation.bid_id = bids.bid_id) "
					+"JOIN items ON (item_bids_relation.bids_itemid = items.item_id) "					
					+"LEFT JOIN user_relations ON user_relations.relation_type = 'Block' AND user_relations.relation_deleted = '0' AND ((user_relations.user_id = " + user_id + " AND bids.receiver_id = user_relations.related_user_id) OR (user_relations.related_user_id = " + user_id + " AND bids.receiver_id = user_relations.user_id)) "
					+"WHERE bids.bidder_id = " + user_id + " AND user_relations.related_user_id IS NULL ) T1 "
				+"INNER JOIN items ON items.item_id = T1.toitemid AND (items.item_deleted = 0 OR (items.item_deleted = 1 AND T1.accepted_by_receiver <> 0))) T2 "
				+"INNER JOIN item_bids_relation ON T2.bidid = item_bids_relation.bid_id) T3 "
				+"INNER JOIN items ON T3.bids_itemid = items.item_id AND (items.item_deleted = 0 OR (items.item_deleted = 1 AND T3.accepted_by_receiver <> 0)) "
				+"ORDER BY bidder_bidunread DESC, receiver_bidunread DESC";
			constants.pool.query(querySelectAllBidsOfUser, function(err, rows) {
				if (err) {
					console.log(username + " failed getting message list by IP : " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
					return response.json({
						"status": language.error_title,
						"message": language.error_bids
					});
				}
				else {
					var receivedbids = []
					var sentbids = []
					var messagesunread = false;
					
					if (rows.length) {
						var lastbidid;
						var receiveditems = [];
						var sentitems = [];
						for (var i=0; i<rows.length; i++) {
							var currentrow = rows[i];
							var currentreceiverid = currentrow.receiver_id;
							var currentbidderid = currentrow.bidder_id;
							var currentbidstatus = currentrow.accepted_by_receiver;
																		
							//if current row indicates a new bid
							if(null == lastbidid || currentrow.bid_id != lastbidid){
								lastbidid = currentrow.bid_id;
								sentitems = [];
								var currentsentitem = new classes.Item(currentrow.optionitemid, currentrow.withitem_name, null, 
									null, null, currentrow.withitem_photo, null, null);
								sentitems.push(currentsentitem);
								receiveditems = [];								
								var currentreceiveditem = new classes.Item(currentrow.toitemid, currentrow.toitem_name, null, 
									null, null, currentrow.toitem_photo, null, null);
								receiveditems.push(currentreceiveditem);	
																
								if(user_id == currentreceiverid){
									var currentreceiver = new classes.User(currentreceiverid);
									
									var currentbiddername = currentrow.u_name;
									var currentbidderphoto = currentrow.u_photo;
									var currentbidder = new classes.User(currentbidderid, currentbiddername, currentbidderphoto);							
									var currentreceivedbid = new classes.Bid(lastbidid, currentbidder, currentreceiver, sentitems, receiveditems, currentbidstatus);
									receivedbids.push(currentreceivedbid);
									
									if(currentrow.receiver_bidunread == 1){
										messagesunread = true;
									}
								}
								else if(user_id == currentbidderid){
									var currentbidder = new classes.User(currentbidderid);						

									var currentreceivername = currentrow.u_name;
									var currentreceiverphoto = currentrow.u_photo;									
									var currentreceiver = new classes.User(currentreceiverid, currentreceivername, currentreceiverphoto);
									var currentsentbid = new classes.Bid(lastbidid, currentbidder, currentreceiver, sentitems, receiveditems, currentbidstatus);
									sentbids.push(currentsentbid);
									
									if(currentrow.bidder_bidunread == 1){
										messagesunread = true;
									}									
								}																
							}							
							else{
								var currentsentitem = new classes.Item(currentrow.optionitemid, currentrow.withitem_name, null, 
									null, null, currentrow.withitem_photo, null, null);
								sentitems.push(currentsentitem);							
								if(user_id == currentreceiverid){
									receivedbids[receivedbids.length - 1].offereditems = sentitems;
									
									if(currentrow.receiver_bidunread == 1){
										messagesunread = true;
									}									
								}
								else if(user_id == currentbidderid){
									sentbids[sentbids.length - 1].offereditems = sentitems;
									
									if(currentrow.bidder_bidunread == 1){
										messagesunread = true;
									}									
								}
							}
						}
					}
					var allbids = {receivedbids: receivedbids, sentbids: sentbids};
			
					if(messagesunread){
						var updatebidderbidunread = "UPDATE bids SET bidder_bidunread = 0 WHERE bidder_id = " + user_id;
						var updatereceiverbidunread = "UPDATE bids SET receiver_bidunread = 0 WHERE receiver_id = " + user_id;
						constants.pool.query(updatebidderbidunread, function(err, rows) {
							if (err) {
								console.log(username + " failed receiving a bid list by IP : " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
							}
							else {
								console.log(username + "updated updatebidderbidunread by IP: " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
							}
						});
						constants.pool.query(updatereceiverbidunread, function(err, rows) {
							if (err) {
								console.log(username + " could not update updatereceiverbidunread by IP: " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
							}
							else {
								console.log(username + " updated updatereceiverbidunread by IP: " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
							}
						});
					}
					console.log(username + "successfully received the bid list by IP : " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
					return response.json({
						"status": language.success_title,
						"message": language.success_bids,
						"response": allbids
					});
				}
			});
		}
	}
	catch (error) {
		return response.json({
			"status": language.error_title,
			"message": language.error_unknownerror
		});
	}
});

app.post('/rejectbid', authentication, function(request, response) {
	try {
		var body = request.body;
		var bid_id = constants.pool.escape(body.bid_id);
		var user_id = body.u_id;
		var u_name = body.username;
		console.log(u_name + "tries to reject bid number : " + bid_id + " by IP: " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
		if (bid_id == null) {
			return response.json({
				"status": language.error_title,
				"message": language.error_invalidbid
			});
		}
		else {
			var querySelectOwner = "SELECT bids.bidder_id, bids.receiver_id, bids.accepted_by_bidder, bids.accepted_by_receiver FROM bids WHERE (bids.bid_id = " + bid_id + ")";
			constants.pool.query(querySelectOwner, function(errSelectOwner, rowsSelectOwner) {
				if (errSelectOwner) {
					return response.json({
						"status": language.error_title,
						"message": language.error_bids
					});
				}
				else {
					if (rowsSelectOwner.length < 1) {
						return response.json({
							"status": language.error_title,
							"message": language.error_deleteditems
						});
					}
					else if (rowsSelectOwner.length == 1) {
						var receiver_id = rowsSelectOwner[0]['receiver_id'];
						var accepted_by_bidder = rowsSelectOwner[0]['accepted_by_bidder'];
						var accepted_by_receiver = rowsSelectOwner[0]['accepted_by_receiver'];
						var bidder_id = rowsSelectOwner[0]['bidder_id'];
						if (user_id == receiver_id) {
							if (accepted_by_receiver == 0) {
								var queryRejectBid = "UPDATE bids SET accepted_by_receiver = 2 WHERE bid_id = " + bid_id;
								constants.pool.query(queryRejectBid, function(errRejectBid, rowsRejectBid) {
									if (errRejectBid) {
										console.log(u_name + "failed rejecting bid number : " + bid_id + " by IP: " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
										return response.json({
											"status": language.error_title,
											"message": language.error_database
										});
									}
									else {
										if (receiver_id === user_id) {
											var updatebidderbidunread = "UPDATE bids SET bidder_bidunread = 1 WHERE bid_id = " + bid_id;
											constants.pool.query(updatebidderbidunread, function(err, rows) {
												if (err) {
													console.log(u_name + " could not update updatebidderbidunread by IP: " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
													return response.json({
														"status": language.success_title,
														"message": language.success_rejectbid
													});
												}
												else {
													console.log(u_name + " updated updatebidderbidunread by IP: " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
													return response.json({
														"status": language.success_title,
														"message": language.success_rejectbid
													});
												}
											});
										}
										else {
											console.log(u_name + "failed rejecting bid number : " + bid_id + " by IP: " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
											return response.json({
												"status": language.error_title,
												"message": language.error_authorization
											});
										}
									}
								});
							}
							else if (accepted_by_receiver == 1) {
								console.log(u_name + " failed rejecting bid number : " + bid_id + " because he/she already rejected it before - by IP: " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
								return response.json({
									"status": language.error_title,
									"message": language.error_rejectedbid
								});
							}
							else if (accepted_by_receiver == 2) {
								console.log(u_name + " failed rejecting bid number : " + bid_id + " because he/she already rejected it before - by IP: " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
								return response.json({
									"status": language.error_title,
									"message": language.error_rejectedbid
								});
							}
							else {
								console.log(u_name + " failed rejecting bid number : " + bid_id + " by IP: " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
								return response.json({
									"status": language.error_title,
									"message": language.error_unknownerror
								});
							}
						}
						else {
							console.log(u_name + " failed rejecting bid number : " + bid_id + " because he/she is not authorized to complete that action - by IP: " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
							return response.json({
								"status": language.error_title,
								"message": language.error_authorization
							});
						}
					}
					else {
						return response.json({
							"status": language.error_title,
							"message": language.error_unknownerror
						});
					}
				}
			});
		}
	}
	catch (error) {
		return response.json({
			"status": language.error_title,
			"message": language.error_unknownerror
		});
	}
});

app.post('/acceptbid', authentication, function(request, response) {
	try {
		var body = request.body;
		var bid_id = constants.pool.escape(body.bid_id);
		var user_id = body.u_id;
		var u_name = body.username;
		console.log(u_name + " tries to accept bid number : " + bid_id + " by IP: " + (request.headers['x-forwarded-for'] ||
			request.connection.remoteAddress));
		if ((bid_id == null || bid_id == undefined)) {
			return response.json({
				"status": language.error_title,
				"message": language.error_invalidbid
			});
		}
		else {
			var querySelectOwner = "SELECT bids.bidder_id, bids.receiver_id, bids.accepted_by_bidder, bids.accepted_by_receiver FROM bids WHERE (bids.bid_id = " + bid_id + ")";
			constants.pool.query(querySelectOwner, function(errSelectOwner, rowsSelectOwner) {
				if (errSelectOwner) {
					return response.json({
						"status": language.error_title,
						"message": language.error_bids
					});
				}
				else {
					if (rowsSelectOwner.length < 1) {
						return response.json({
							"status": language.error_title,
							"message": language.error_deleteditems
						});
					}
					else if (rowsSelectOwner.length == 1) {
						var receiver_id = rowsSelectOwner[0]['receiver_id'];
						var accepted_by_bidder = rowsSelectOwner[0]['accepted_by_bidder'];
						var accepted_by_receiver = rowsSelectOwner[0]['accepted_by_receiver'];
						var bidder_id = rowsSelectOwner[0]['bidder_id'];
						if (user_id == receiver_id) {
							if (accepted_by_receiver == 0) {
								var queryAcceptBid = "UPDATE bids SET accepted_by_receiver = 1 WHERE bid_id = " + bid_id;
								constants.pool.query(queryAcceptBid, function(errAcceptBid , rowsAcceptBid ) {
									if (errAcceptBid) {
										console.log(u_name + " failed accepting bid number : " + bid_id + " by IP: " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
										return response.json({
											"status": language.error_title,
											"message": language.error_database,
											"response": err
										});
									}
									else {
										var updatebidderbidunread = "UPDATE bids SET bidder_bidunread = 1 WHERE bid_id = " + bid_id;
										constants.pool.query(updatebidderbidunread, function(err, rows) {
											if (err) {
												console.log(u_name + " successfully accepted bid number : " + bid_id + " by IP: " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
												return response.json({
													"status": language.success_title,
													"message": language.success_acceptbid
												});
											}
											else {
												console.log(u_name + " successfully accepted bid number : " + bid_id + " by IP: " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
												return response.json({
													"status": language.success_title,
													"message": language.success_acceptbid
												});
											}
										});
									}
								});
							}
							else if (accepted_by_receiver == 1) {
								console.log(u_name + " failed accepting bid number : " + bid_id + " by IP: " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
								return response.json({
									"status": language.error_title,
									"message": language.error_acceptedbid
								});
							}
							else if (accepted_by_receiver == 2) {
								console.log(u_name + " failed accepting bid number : " + bid_id + " by IP: " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
								return response.json({
									"status": language.error_title,
									"message": language.error_rejectedbid
								});
							}
							else {
								console.log(u_name + " failed accepting bid number : " + bid_id + " by IP: " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
								return response.json({
									"status": language.error_title,
									"message": language.error_unknownerror
								});
							}
						}
						else {
							console.log(u_name + " failed accepting bid number : " + bid_id + " by IP: " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
							return response.json({
								"status": language.error_title,
								"message": language.error_authorization
							});
						}
					}
					else {
						console.log(u_name + " failed accepting bid number : " + bid_id + " by IP: " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
						return response.json({
							"status": language.error_title,
							"message": language.error_unknownerror
						});
					}
				}
			});
		}
	}
	catch (error) {
		return response.json({
			"status": language.error_title,
			"message": language.error_unknownerror
		});
	}
});

app.post('/createbid', authentication, function(request, response) {
	try {
		var body = request.body;
		var u_name = body.username;
		console.log(u_name + "tries to create a new bid by IP: " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
		var bidItems = body.item_list;
		var bidderId = body.u_id;
		var to_item = constants.pool.escape(body.to_item);
		if (bidderId == null || bidItems == null || to_item == null) {
			return response.json({
				"status": language.error_title,
				"message": language.error_createbid
			});
		}		
		var startingQuery = "";
		for (var c = 0; c < bidItems.length; c++) {
			var itemidForSelect = "";
			try {
				itemidForSelect = bidItems[c]['item_id'];
			}
			catch (err) {}
			var tempStr = itemidForSelect;
			startingQuery += tempStr;
			if (bidItems.length - c > 1) {
				startingQuery += ",";
			}
		}
		var querySelectReceiver = "SELECT users.u_id, users.u_name, users.u_email, users.u_notificationforbids FROM items JOIN users WHERE items.item_id =" + to_item + " AND items.item_ownerid = users.u_id";
		constants.pool.query(querySelectReceiver, function(errSelectReceiver, rowsSelectReceiver) {
			if (errSelectReceiver) {
				return response.json({
					"status": language.error_title,
					"message": language.error_database,
					"response": errSelectReceiver
				});
			}
			else {
				if (rowsSelectReceiver.length != 1){
					return response.json({
						"status": language.error_title,
						"message": language.error_unknownerror
					});
				}
				var receiver_id = rowsSelectReceiver[0]['u_id'];
				var receiver_name = rowsSelectReceiver[0]['u_name'];
				var receiver_email = rowsSelectReceiver[0]['u_email'];
				var receiver_notificationforbids = rowsSelectReceiver[0]['u_notificationforbids'];
				//Check if user is blocked
				var queryCheckBlock = "SELECT relation_type "
									+"FROM user_relations "
									+"WHERE user_relations.user_id = "+ receiver_id +" AND user_relations.related_user_id = "+ bidderId +" AND user_relations.relation_type = 'Block' AND user_relations.relation_deleted = '0'";

				constants.pool.query(queryCheckBlock, function(errCheckBlock, rowsCheckBlock) {
					if (errCheckBlock) {
						return response.json({
							"status": language.error_title,
							"message": language.error_database,
							"response": errCheckBlock
						});
					}
					else {	
						var resultLength = rowsCheckBlock.length;
						if(resultLength){
							return response.json({
								"status": language.error_title,
								"message": language.error_blockeduser
							});
						}
						else{
							var querySelectItemsOwner = "SELECT items.item_ownerid FROM items WHERE items.item_id IN (" + startingQuery + ")";
							constants.pool.query(querySelectItemsOwner, function(errSelectItemsOwner, rowsSelectItemsOwner) {
								if (errSelectItemsOwner) {
									return response.json({
										"status": language.error_title,
										"message": language.error_database,
										"response": errSelectItemsOwner
									});
								}
								else {
									if (rowsSelectItemsOwner.length == bidItems.length && rowsSelectItemsOwner.length != 0) {
										for (var a = 0; a < rowsSelectItemsOwner.length; a++) {
											var itemOwnerIds = rowsSelectItemsOwner[a]['item_ownerid'];
											if (itemOwnerIds != bidderId) {
												console.log(u_name + " failed creating a new bid by IP: " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
												return response.json({
													"status": language.error_title,
													"message": language.error_authorization
												});
											}
										}
									}
									else {
										console.log(u_name + " failed creating a new bid by IP: " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
										return response.json({
											"status": language.error_title,
											"message": language.error_authorization
										});
									}
									var queryInsertBid = "INSERT INTO bids (bid_id, toitem_id, bidder_id, receiver_id) VALUES (" + 0 + " ," + to_item + " ," + bidderId + " ," + receiver_id + ")";
									constants.pool.query(queryInsertBid, function(errInsertBid, rowsInsertBid) {
										if (errInsertBid) {
											console.log(u_name + " failed creating a new bid by IP: " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
											return response.json({
												"status": language.error_title,
												"message": language.error_createbid,
												"response": errInsertBid
											});
										}
										else {
											var lastId = rowsInsertBid.insertId
											var bidValuesQuery = "";
											for (var i = 0; i < bidItems.length; i++) {
												var itemid = "";
												try {
													itemid = bidItems[i]['item_id'];
												}
												catch (err) {}
												var tempStr = "(" + lastId + "," + itemid + ")";
												bidValuesQuery += tempStr;
												if (bidItems.length - i > 1) {
													bidValuesQuery += ",";
												}
											}
											var queryInsertItemBidRelation = "INSERT INTO item_bids_relation (bid_id, bids_itemid) VALUES" + bidValuesQuery + ";";
											constants.pool.query(queryInsertItemBidRelation, function(errInsertItemBidRelation, rowsInsertItemBidRelation) {
												if (errInsertItemBidRelation) {
													var queryDeleteUnsuccessfulBid = "DELETE FROM bids WHERE bid_id = " + lastId
													constants.pool.query(queryDeleteUnsuccessfulBid, function(errDeleteUnsuccessfulBid, rowsDeleteUnsuccessfulBid) {
														if (errDeleteUnsuccessfulBid) {
															return response.json({
																"status": language.error_title,
																"message": language.error_createbid,
																"response": errDeleteUnsuccessfulBid
															});
														}
														else {
															return response.json({
																"status": language.error_title,
																"message": language.success_createbid
															});
														}
													});
												}
												else {
													console.log(u_name + " successfully created a new bid by IP: " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
													if(null != receiver_notificationforbids && receiver_notificationforbids){
													//TODO mail
														var mailOptions = {
															from: '"Swaplat" <support@swaplat.com>', // sender address
															to: receiver_email, // list of receivers
															subject: 'Teklifiniz var', // Subject line
															html: 'Merhaba '+ receiver_name +', '
																+'<p>Swaplat\'a koymuş olduğun ilana yeni bir teklif verildi. Aşağıdaki butona tıklayarak teklifin detaylarını inceleyebilirsin. </p> '
																+'<a href="http://localhost:8888/swaplat/offer.php?offerid='+ lastId +'"> <span style="display: inline-block; font-size: 16px; padding: 10px 18px; color: #fff; background-color: #427951; vertical-align: middle; font-weight: bold; text-decoration: none; border: 1px solid #EFF2EB; border-radius: 4px;">Teklife Git</span></a>'
														};
														// send mail with defined transport object
														constants.transporter.sendMail(mailOptions, (errorMail, info) => {
															if (errorMail) {
																console.log("Failed to create a new user with username " + u_name + " using IP " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));									
																return response.json({
																	"status": language.error_title,
																	"message": language.error_email,
																	"response": errorMail
																});
															}
															else {
																return response.json({
																	"status": language.success_title,
																	"message": language.success_createbid
																});
															}
														});
													}
													return response.json({
														"status": language.success_title,
														"message": language.success_createbid
													});
												}
											});
										}
									});							
								}
							});
						}
					}
				});									
			}
		});
	}
	catch (error) {
		return response.json({
			"status": language.error_title,
			"message": language.error_unknownerror,
			"response": error
		});
	}
});

app.post('/getmessagerlist', authentication, function(request, response) {
	try {
		var body = request.body;
		var ownerId = body.u_id;
		var u_name = body.username;
		console.log(u_name + " tries to get messager list with IP " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
		if (ownerId == null) {
			console.log(u_name + " failed receiving messager list with IP " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
			return response.json({
				"status": language.error_title,
				"message": language.error_login
			});
		}
		else {
			var querySelectMessagers =
				"SELECT userid, username, userphoto, MAX(unreadmessages) AS unreadmessagenumber, MAX(maxdate) AS lastmessagetime "
				+"FROM (SELECT users.u_id userid, users.u_name username, users.u_photo userphoto, '0' AS unreadmessages, MAX(messages.message_time) AS maxdate "
						+"FROM users "
						+"JOIN messages ON (messages.to_uid = users.u_id AND messages.u_id = " + ownerId + ") "
						+"GROUP BY username "
						+"UNION ALL "
						+"SELECT users.u_id userid, users.u_name username, users.u_photo userphoto, SUM(messages.message_unread) AS unreadmessages, MAX(messages.message_time) AS maxdate "
						+"FROM users "
						+"JOIN messages ON (messages.to_uid = " + ownerId + " AND messages.u_id = users.u_id) "
						+"GROUP BY username) unionedtable "
				+"LEFT JOIN user_relations ON user_relations.relation_type = 'Block' AND user_relations.relation_deleted = '0' AND ((user_relations.user_id = " + ownerId + " AND userid = user_relations.related_user_id) OR (user_relations.related_user_id = " + ownerId + " AND userid = user_relations.user_id)) "
				+"WHERE (user_relations.related_user_id IS NULL) "
				+"GROUP BY username "
				+"ORDER BY lastmessagetime DESC";
			
			constants.pool.query(querySelectMessagers, function(err, rows) {
				if (err) {
					console.log(u_name + " failed receiving messager list with IP " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
					return response.json({
						"status": language.error_title,
						"message": language.error_messagers
					});
				}
				else {
					var messagers = [];
					for (var i = 0; i < rows.length; i++) {
						var currentrow = rows[i];
						var user = new classes.User(currentrow.userid, currentrow.username, currentrow.userphoto, null, null, 
							currentrow.unreadmessagenumber.toString('utf8'), currentrow.lastmessagetime);
						messagers.push(user);
					}
					console.log(u_name + " successfully received messager list with IP " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
					return response.json({
						"status": language.success_title,
						"message": language.success_messagers,
						"response": messagers
					});
				}
			});
		}
	}
	catch (error) {
		return response.json({
			"status": language.error_title,
			"message": language.error_unknownerror,
			"response": error
		});
	}
});

app.post('/getmessagesbyuser', authentication, function(request, response) {
	try {
		var body = request.body;
		var ownerId = body.u_id;
		var byUserId = constants.pool.escape(body.by_uid);
		var u_name = body.username;
		
		console.log(u_name + " tries to get messages by user id : " + byUserId + "  with IP " + (request.headers[
			'x-forwarded-for'] || request.connection.remoteAddress));
			
		if (ownerId == null) {
			return response.json({
				"status": language.error_title,
				"message": language.error_login
			});
		}
		else if (byUserId == null) {
			return response.json({
				"status": language.error_title,
				"message": language.error_invaliduser
			});
		}
		else {
			var querySelectMessages = "SELECT messages.message_id, messages.u_id, messages.to_uid, messages.message_text, messages.message_time, messages.message_unread, items.item_id, items.item_name, items.item_photo"
				+ " FROM messages LEFT JOIN items ON (messages.related_item_id = items.item_id)" 
				+ " WHERE (u_id = " + ownerId + " AND to_uid = " + byUserId + ") OR (u_id = " + byUserId + " AND to_uid = " + ownerId + ")" 
				+ " ORDER BY message_time, message_id ASC";
			
			constants.pool.query(querySelectMessages, function(err, rows) {
				if (err) {
					return response.json({
						"status": language.error_title,
						"message": language.error_messages
					});
				}
				else {
					var messages = [];
					for (var i = 0; i < rows.length; i++) {
						var currentrow = rows[i];
						var currentitem = new classes.Item(currentrow.item_id, currentrow.item_name, null, null, null, currentrow.item_photo);
						var currentmessage = new classes.Message(currentrow.message_id, currentrow.u_id, currentrow.to_uid, currentrow.message_text, currentrow.message_time, currentitem);
						var currentmessageunread = currentrow.message_unread;
						messages.push(currentmessage);
					}

					if(currentmessageunread == 1){
						var queryMakeMessagesRead = "UPDATE messages SET message_unread = 0 WHERE to_uid = " + ownerId + " AND u_id = " + byUserId;
						console.log("queryMakeMessagesRead: " + queryMakeMessagesRead);					
						constants.pool.query(queryMakeMessagesRead, function(err, result) {
							if (err) {
								console.log(u_name + "failed to make messages of " + byUserId + " read with IP " + (request.headers[
								'x-forwarded-for'] || request.connection.remoteAddress));
							}
						});						
					}
					return response.json({
						"status": language.success_title,
						"message": language.success_messages,
						"response": messages
					});
				}
			});
		}
	}
	catch (error) {
		return response.json({
			"status": language.error_title,
			"message": language.error_unknownerror,
			"response": error
		});
	}
});

app.post('/sendmessage', authentication, function(request, response) {
	try {
		var body = request.body;
		var senderId = constants.pool.escape(body.u_id);
		var receiverId = constants.pool.escape(body.to_uid);
		var messageText = constants.pool.escape(body.message_text);
		var relatedItemId = constants.pool.escape(body.related_item_id);
		var emptyMessageTest = /^\s+$/.test(messageText);
		var username = body.username;
		console.log(username + "tries to send a message by IP : " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
		if (senderId == null || receiverId == null) {
			return response.json({
				"status": language.error_title,
				"message": language.error_sendmessage
			});
		}
		else if (messageText == null) {
			console.log(username + "failed sending a message by IP : " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
			return response.json({
				"status": language.error_title,
				"message": language.error_blankmessage
			});
		}
		else {
			//Check if user is blocked
			var queryCheckBlock = "SELECT relation_type "
								+"FROM user_relations "
								+"WHERE user_relations.user_id = "+ receiverId +" AND user_relations.related_user_id = "+ senderId +" AND user_relations.relation_type = 'Block' AND user_relations.relation_deleted = '0'";
							
			constants.pool.query(queryCheckBlock, function(errCheckBlock, rowsCheckBlock) {
				if (errCheckBlock) {
					return response.json({
						"status": language.error_title,
						"message": language.error_database,
						"response": errCheckBlock
					});
				}
				else {	
					var resultLength = rowsCheckBlock.length;
					if(resultLength){
						return response.json({
							"status": language.error_title,
							"message": language.error_blockeduser
						});
					}
					else{
			// 			var time = moment().format('MMMM Do YYYY, h:mm:ss a');
						var queryNewMessage = 
							"INSERT INTO messages (message_id, u_id, to_uid, related_item_id, message_text, message_unread) "
							+"VALUES (" + 0 + ",'" + senderId + "'," + receiverId + "," + relatedItemId + "," + messageText + "," + 1 + ")";
						constants.pool.query(queryNewMessage, function(err, result) {
							if (err) {
								return response.json({
									"status": language.error_title,
									"message": language.error_database,
									"response": err
								});
							}
							else {
								return response.json({
									"status": language.success_title,
									"message": language.success_sendmessage
								});
							}
						});					
					}
				}
			});
		}
	}
	catch (error) {
		return response.json({
			"status": language.error_title,
			"message": language.error_unknownerror,
			"response": error
		});
	}
});

app.post('/search', function(request, response) {
	function callSearchItemsQuery(request, response, querySearchItems){
		constants.pool.query(querySearchItems, function(err, rows) {
		if (err) {
				response.json({
					"status": language.error_title,
					"message": language.error_database
				});
			}
			else {
				var object = {} // empty Object
				var key = 'items';
				object[key] = []; // empty Array, which you can push() values into
				var resultLength = rows.length;
				if (resultLength < 1) {
					var searchedFailedWhereQuery =
						"SELECT cities.c_name, categories.category_name FROM cities, categories WHERE 1 = 1 ";
					if (!(item_categoryForFilter == undefined)) {
						searchedFailedWhereQuery += " AND (category_id = " + constants.pool.escape(item_categoryForFilter) + ")";
					}
					if (!(locationf == undefined)) {
						searchedFailedWhereQuery += " AND (c_code = " + constants.pool.escape(locationf) + ")";
					}
					constants.pool.query(searchedFailedWhereQuery, function(err, rows) {
						if (err) {
							response.json({
								"status": language.error_title,
								"message": language.error_database
							});
						}
						else {
							var a = ""
							var b = "";
							if (!(locationf == undefined)) {
								a = rows[0]['c_name'];
							}
							if (!(item_categoryForFilter == undefined)) {
								b = rows[0]['category_name'];
							}
							return response.json({
								"status": language.error_title,
								"message": language.success_searchnotfound,
								"categoryfilter": b,
								"locfilter": a
							});
						}
					});
				}
				else {
					for (var i = 0; i < resultLength; i++) {
						var item_id = rows[i]['item_id'];
						var item_name = rows[i]['item_name'];
						var item_desc = rows[i]['item_desc'];
						var item_category = rows[i]['item_category'];
						var item_photo = rows[i]['item_photo'];
						var item_date = rows[i]['item_date'];
						var item_ownerid = rows[i]['item_ownerid'];
						var owner_name = rows[i]['u_name'];
						var city = rows[i]['c_name'];
						var user_photo = rows[i]['u_photo'];
						var citycode = rows[i]['c_code'];
						var item_owner = new classes.User(item_ownerid, owner_name, user_photo, city);
						var item = new classes.Item(item_id, item_name, item_desc, item_category, null, item_photo, item_date, item_owner);
						object[key].push(item);
						if (!(item_categoryForFilter == undefined)) {
							categoryfilter = rows[0]['category_name'];
						}
						if (!(locationf == undefined || locationf == 'NULL')) {
							locfilter = rows[0]['c_name'];
						}
					}
					return response.json({
						"status": language.success_title,
						"categoryfilter": categoryfilter,
						"locfilter": locfilter,
						"items_found": object
					});
				}
			}
		});
	}
	try {
		var body = request.body;	
		var locfilter = "ALL";
		var categoryfilter = "ALL"
		var word = body.word;
		var locationf = body.location;
		var item_categoryForFilter = body.category;
		if (word == null) {
			word = "";
		}
		var regexforsearchinput = /^[a-zA-Z0-9-_\u00E7\u011F\u0131\u015F\u00F6\u00FC\u00C7\u011E\u0130\u015E\u00D6\u00DC\s]*$/;		
		var inputCheck = regexforsearchinput.test(word);
		if (!inputCheck) {
			return response.json({
				"status": language.error_title,
				"message": language.error_invalidsearch
			});
		}
		else {
			var u_token = body.u_token;
			if (null != u_token) {
				authentication(request, response, function(){		
					var user_id = constants.pool.escape(body.u_id);
					if (null == user_id) {
						return response.json({
							"status": language.error_title,
							"message": language.error_invaliduser
						});
					}
					var querySearchItems =
						"SELECT users.u_name, users.u_photo, items.`item_id`, items.item_name, items.item_desc, items.item_category, items.item_photo, items.item_ownerid, items.item_date, cities.c_name, cities.c_code, categories.category_name "
						+"FROM items "
						+"JOIN users ON (items.item_ownerid = users.u_id) "
						+"JOIN cities ON (cities.c_code = users.u_location) "
						+"JOIN categories ON (categories.category_id = items.item_category) "
						+"LEfT JOIN user_relations ON user_relations.relation_type = 'Block' AND user_relations.relation_deleted = '0' AND ((user_relations.user_id = "+ user_id +" AND users.u_id = user_relations.related_user_id) OR (user_relations.related_user_id = "+ user_id +" AND users.u_id = user_relations.user_id)) "				
						+"WHERE ((items.item_name LIKE " + constants.pool.escape('%' + word + '%') + ") OR (items.item_desc LIKE " + constants.pool.escape('%' + word + '%') + ")) AND (user_relations.related_user_id IS NULL) "
					if (!(item_categoryForFilter == null)) {
						querySearchItems += " AND (items.item_category = " + constants.pool.escape(item_categoryForFilter) + ")";
					}
					if (!(locationf == null)) {
						querySearchItems += " AND (cities.c_code = " + constants.pool.escape(locationf) + ")";
					}
					querySearchItems += " AND items.item_deleted = 0 ORDER BY items.item_date DESC";
					callSearchItemsQuery(request, response, querySearchItems);
				});	
			}
			else{
				var querySearchItems =
					"SELECT users.u_name, users.u_photo, items.`item_id`, items.item_name, items.item_desc, items.item_category, items.item_photo, items.item_ownerid, items.item_date, cities.c_name, cities.c_code, categories.category_name "
					+"FROM items "
					+"JOIN users ON (items.item_ownerid = users.u_id) "
					+"JOIN cities ON (cities.c_code = users.u_location) "
					+"JOIN categories ON (categories.category_id = items.item_category) "
					+"WHERE ((items.item_name LIKE " + constants.pool.escape('%' + word + '%') + ") OR (items.item_desc LIKE " + constants.pool.escape('%' + word + '%') + ")) "
				if (item_categoryForFilter != null) {
					querySearchItems += " AND (items.item_category = " + constants.pool.escape(item_categoryForFilter) + ")";
				}
				if (locationf != null) {
					querySearchItems += " AND (cities.c_code = " + constants.pool.escape(locationf) + ")";
				}
				querySearchItems += " AND items.item_deleted = 0 ORDER BY items.item_date DESC";
				callSearchItemsQuery(request, response, querySearchItems);			
			}		
		}
	}
	catch (error) {
		return response.json({
			"status": language.error_title,
			"message": language.error_unknownerror
		});
	}
});
app.get('/getcategories', function(request, response) {
	try {
		var getCategoriesQuery = "SELECT category_id, category_name FROM categories";
		constants.pool.query(getCategoriesQuery, function(err, rows) {
			if (err) {
				return response.json({
					"status": language.error_title,
					"message": language.error_database,
					"response": err
				});
			}
			else {
				return response.json({
					"status": language.success_title,
					"message": language.success_categories,
					"Categories": rows
				});
			}
		});
	}
	catch (error) {
		return response.json({
			"status": language.error_title,
			"message": language.error_unknownerror
		});
	}
});
app.post('/deleteitem', authentication, function(request, response) {
	try {
		var body = request.body;
		var u_id = body.u_id;
		var item_id = constants.pool.escape(body.item_id);
		var u_name = body.username;
		console.log(u_name + " tries to delete item with itemid : " + item_id + " from IP " + (request.headers[
			'x-forwarded-for'] || request.connection.remoteAddress));
		if ((item_id == null || item_id == undefined)) {
			console.log(u_name + " failed deleting item with itemid : " + item_id + " from IP " + (request.headers[
				'x-forwarded-for'] || request.connection.remoteAddress));
			return response.json({
				"status": language.error_title,
				"message": language.error_itemnotfound
			});
		}
		var selectToDeleteItemQuery = "SELECT item_ownerid FROM items WHERE item_deleted = 0 AND item_id = " + item_id;
		constants.pool.query(selectToDeleteItemQuery, function(err, rows) {
			if (err) {
				console.log(u_name + " failed deleting item with itemid : " + item_id + " from IP " + (request.headers[
					'x-forwarded-for'] || request.connection.remoteAddress));
				return response.json({
					"status": language.error_title,
					"message": language.error_database,
					"response": err
				});
			}
			else {
				var userid = rows[0]['item_ownerid']
				if (u_id == userid) {
					var deleteItemQuery = "UPDATE items SET item_deleted = '1' WHERE item_id = " + item_id;
					constants.pool.query(deleteItemQuery, function(err, rows) {
						if (err) {
							console.log(u_name + " failed deleting item with itemid : " + item_id + " from IP " + (request.headers[
								'x-forwarded-for'] || request.connection.remoteAddress));
							return response.json({
								"status": language.error_title,
								"message": language.error_database,
								"response": err
							});
						}
						else {
							console.log(u_name + " successfully deleted item with itemid : " + item_id + " from IP " + (request.headers[
								'x-forwarded-for'] || request.connection.remoteAddress));
							return response.json({
								"status": language.success_title,
								"message": language.success_deleteitem
							});
						}
					});
				}
				else {
					return response.json({
						"status": language.error_title,
						"message": language.error_authorization
					});
				}
			}
		});
	}
	catch (error) {
		return response.json({
			"status": language.error_title,
			"message": language.error_unknownerror,
			"response": error
		});
	}
});

app.post('/getblockedusers', authentication, function (request, response) {
	try {
		var body = request.body;
		var u_name = body.username;
		var user_id = body.u_id;
		console.log(u_name + " tries to get blocked users with user id : " + user_id + " from IP " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
		if (user_id == null) {
			console.log(u_name + " failed to get blocked users with user id : " + user_id + " from IP " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
			return response.json({
				"status": language.error_title,
				"message": language.error_invaliduser
			});
		}
		var queryGetBlockedUsers = 
		"SELECT users.u_id, users.u_name, users.u_photo "
		+"FROM users "
		+"LEFT JOIN user_relations ON user_relations.relation_type = 'Block' AND user_relations.relation_deleted = '0' AND user_relations.user_id = " + user_id + " AND users.u_id = user_relations.related_user_id "
		+"WHERE user_relations.related_user_id IS NOT NULL";
		constants.pool.query(queryGetBlockedUsers, function(errGetBlockedUser, rowsGetBlockedUser) {
			if (errGetBlockedUser) {
				console.log(u_name + " failed to get blocked users with user id : " + user_id + " from IP " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
				return response.json({
					"status": language.error_title,
					"message": language.error_database,
					"response": errInsertBlockedUser
				});
			}
			else {
			var blockedusers = [];
				if (rowsGetBlockedUser.length == 0) {
					return response.json({
						"status": language.success_title,
						"message": language.error_blockedusers,
						"response": blockedusers
					});
				}
				else {
					for (var i = 0; i < rowsGetBlockedUser.length; i++) {
						var currentrow = rowsGetBlockedUser[i];
						var currentowner = new classes.User(currentrow.u_id, currentrow.u_name, currentrow.u_photo);
						blockedusers.push(currentowner);
					}
					return response.json({
						"status": language.success_title,
						"message": language.success_blockedusers,
						"response": blockedusers
					});					
				}			
			}
		});
	}
	catch (error) {
		return response.json({
			"status": language.error_title,
			"message": language.error_unknownerror,
			"response": error
		});
	}
});

app.post('/blockuser', authentication, function (request, response) {
	try {
		var body = request.body;
		var u_name = body.username;
		var user_id = body.u_id;	
		var related_user_id = body.related_user_id;
		console.log(u_name + " tries to block user with user id : " + related_user_id + " from IP " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
		if (related_user_id == null || user_id == null) {
			console.log(u_name + " failed to block user with user id : " + related_user_id + " from IP " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
			return response.json({
				"status": language.error_title,
				"message": language.error_invaliduser
			});
		}
		var queryDeleteBlockedUser = 
		"DELETE from user_relations "
		+"WHERE user_id = "+ user_id +" AND related_user_id = "+ related_user_id +" AND relation_type = 'Block' AND relation_deleted = '1'";
		console.log("queryDeleteBlockedUser: " + queryDeleteBlockedUser);
		constants.pool.query(queryDeleteBlockedUser, function(errDeleteBlockedUser, rowsDeleteBlockedUser) {
			if (errDeleteBlockedUser) {
				console.log(u_name + " failed to block user with user id : " + related_user_id + " from IP " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
				return response.json({
					"status": language.error_title,
					"message": language.error_database,
					"response": errDeleteBlockedUser
				});
			}
			else {
				var queryInsertBlockedUser = 
				"INSERT INTO user_relations (user_id, related_user_id, relation_type) "
				+"VALUES ("+ user_id +", "+ related_user_id +", 'Block')";
				constants.pool.query(queryInsertBlockedUser, function(errInsertBlockedUser, rowsInsertBlockedUser) {
					if (errInsertBlockedUser) {
						console.log(u_name + " failed to block user with user id : " + related_user_id + " from IP " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
						return response.json({
							"status": language.error_title,
							"message": language.error_database,
							"response": errInsertBlockedUser
						});
					}
					else {
						return response.json({
							"status": language.success_title,
							"message": language.success_block
						});
					}
				});
			}
		});
	}
	catch (error) {
		return response.json({
			"status": language.error_title,
			"message": language.error_unknownerror,
			"response": error
		});
	}
});

app.post('/removeblockuser', authentication, function (request, response) {
	try {
		var body = request.body;
		var u_name = body.username;
		var user_id = body.u_id;	
		var related_user_id = body.related_user_id;
		console.log(u_name + " tries to remove block user with user id : " + related_user_id + " from IP " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
		if (related_user_id == null || user_id == null) {
			console.log(u_name + " failed to remove block user with user id : " + related_user_id + " from IP " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
			return response.json({
				"status": language.error_title,
				"message": language.error_invaliduser
			});
		}
		var queryRemoveBlockedUser = 
		"UPDATE user_relations SET relation_deleted="+1+" "
		+"WHERE user_id = "+ user_id +" AND related_user_id = "+ related_user_id +" AND relation_type = 'Block'";
		constants.pool.query(queryRemoveBlockedUser, function(errRemoveBlockedUser, rowsRemovBlockedUser) {
			if (errRemoveBlockedUser) {
				console.log(u_name + " failed to block user with user id : " + related_user_id + " from IP " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
				return response.json({
					"status": language.error_title,
					"message": language.error_database,
					"response": errRemoveBlockedUser
				});
			}
			else {
				console.log(u_name + " succeed to block user with user id : " + related_user_id + " from IP " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));			
				return response.json({
					"status": language.success_title,
					"message": language.success_removeblock
				});
			}
		});
	}
	catch (error) {
		console.log(u_name + " failed to block user with user id : " + related_user_id + " from IP " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));	
		return response.json({
			"status": language.error_title,
			"message": language.error_unknownerror,
			"response": error
		});
	}
});

app.use(formidable());
var cloudinary = require('cloudinary');
cloudinary.config({
	cloud_name: 'hs6erjw3p',
	api_key: '146685331886787',
	api_secret: 'rilyejcSqoFw81fLP5dRIezouL0'
});

var bindToRequestBody = function(request, response, next) {
	try {
		var input = request.fields;
		for(var key in input){
			if (input.hasOwnProperty(key)) {
				request.body[key] = input[key];
				continue;
    		}
		}
		return next();
	}
	catch (error) {
		return response.json({
			"status": language.error_title,
			"message": language.error_unknownerror,
			"response": error
		});
	}
}

app.post('/getitem2/:itemid', bindToRequestBody, function(request, response) {
function getItem(user_id){
		var getItemInfoQuery =
			"SELECT items.item_name, items.item_desc, items.item_category, item_photo, items.item_date, users.u_name, users.u_id, users.u_photo, users.u_info, cities.c_name, categories.category_name "
			+"FROM items "
			+"JOIN users ON (items.item_ownerid = users.u_id) "
			+"JOIN cities ON (users.u_location = cities.c_code) "
			+"JOIN categories ON (categories.category_id = items.item_category) "
			+"WHERE items.item_id = " + item_id + " AND items.item_deleted = 0";
		constants.pool.query(getItemInfoQuery, function(err, rows) {
			if (err) {
				response.json({
					"status": language.error_title,
					"message": language.error_database
				});
			}
			else {
				try {
					var resultLength = rows.length;
					if (resultLength < 1) {
// 						return response.json({
// 							"status": language.error_title,
// 							"message": language.error_itemnotfound
// 						});
						response.render('item', { user_id: null, categories: null, item: null});
					}
					else if (resultLength == 1) {
						var currentrow = rows[0];
						var item_owner = new classes.User(currentrow.u_id, currentrow.u_name, constants.photo_directory_50 + currentrow.u_photo, currentrow.c_name, currentrow.c_code, null, null, null, null, currentrow.u_info);
						var item = new classes.Item(item_id.replace(/'/g,""), currentrow.item_name, currentrow.item_desc, currentrow.item_category, currentrow.category_name, constants.photo_directory_50 + currentrow.item_photo, moment(currentrow.item_date).locale("tr").fromNow(), item_owner);

						var categories;
						var getCategoriesQuery = "SELECT category_id, category_name FROM categories";
						constants.pool.query(getCategoriesQuery, function(err, rows) {
							if (!err) {
								categories = rows;
							}
							response.render('item', { user_id: user_id, categories: categories, item: item});
						});
					}
					else {
						return response.json({
							"status": language.error_title,
							"message": language.error_multipleitemfound
						});
					}
				}
				catch (error) {
					response.json({
						"status": language.error_title,
						"message": language.error_userinput
					});
				}
			}
		});
}
	try {
		var body = request.body;
		var u_token = body.u_token;
		var item_id = constants.pool.escape(request.params.itemid);
		if (item_id == null) {
			return response.json({
				"status": language.error_title,
				"message": language.error_invaliditem
			});
		}
		
		if (null != u_token) {
			authentication(request, response, function(){		
				var user_id = constants.pool.escape(body.u_id);
				if (null == user_id) {
					return response.json({
						"status": language.error_title,
						"message": language.error_invaliduser
					});
				}
				getItem(user_id);
			});
		}
		else{
			getItem();
		}
	}
	catch (error) {
		response.json({
			"status": language.error_title,
			"message": language.error_unknownerror
		});
	}
});

app.post('/uploaditem', bindToRequestBody, authentication, function(request, response) {
	function uploadItem(request, response, itemphotoname){
		var queryInsertItem =
			"INSERT INTO items (item_id, item_name, item_desc, item_category, item_photo, item_ownerid) VALUES (" + 0 +
			"," + item_name + "," + item_desc + "," + item_category + "," + itemphotoname + "," + u_id + ")";
			console.log("queryInsertItem: " + queryInsertItem);
		constants.pool.query(queryInsertItem, function(errInsertItem, rowsInsertItem) {
			if (errInsertItem) {
				console.log((request.headers['x-forwarded-for'] || request.connection.remoteAddress) + " failed to upload a new item" );
				if (itemphotoname != constants.CLOUDINARY_ANON_ITEM_PHOTO){
					cloudinary.uploader.destroy(itemphotoname, function(err, result) {
					});
				}
				return response.json({
					"status": language.error_title,
					"message": language.error_database,
					"response": errInsertItem
				});
			}
			else {
				console.log(u_name + " successfully uploaded a new item with IP " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
				return response.json({
					"status": language.success_title,
					"message": language.success_createitem
				});
			}
		});
	}
	try {
		var body = request.body;
		var u_name = body.username;
		console.log(u_name + " tries to upload a new item with IP " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
		var u_id = request.body.u_id;
		var item_id = constants.pool.escape(body.item_id);
		if(null == body.item_name || "" == body.item_name){
			return response.json({
				"status": language.error_title,
				"message": language.error_itememptyitemname
			});
		}
		var item_name = constants.pool.escape(body.item_name);		
// 		if(null == body.item_desc || "" == body.item_desc){
// 			return response.json({
// 				"status": language.error_title,
// 				"message": language.error_itememptyitemdescription
// 			});
// 		}
		var item_desc = constants.pool.escape(body.item_desc);
		if(null == body.item_category || "" == body.item_category){
			return response.json({
				"status": language.error_title,
				"message": language.error_itememptyitemcategory
			});
		}
		var item_category = constants.pool.escape(body.item_category);
		var u_token = body.u_token;
		var photo = request.files.photo;
		var phototype = request.files.photo.type;
		var path = request.files.photo.path;
		if (null != phototype && null != path) {
			if (phototype.indexOf("jpeg") == -1 && phototype.indexOf("jpg") == -1 && phototype.indexOf("png") == -1 && phototype.indexOf("application/octet-stream") == -1) {
				console.log((request.headers['x-forwarded-for'] || request.connection.remoteAddress) + " failed to upload a new item" );
				return response.json({
					"status": language.error_title,
					"message": language.error_filetype
				});
			}
			else {
			//If there is a photo with jpeg, jpg or png extension OR no photo at all (application/octet-stream)				
				var item_photo_name = constants.pool.escape(constants.CLOUDINARY_ANON_ITEM_PHOTO);
				if (phototype.indexOf("jpeg") != -1 || phototype.indexOf("jpg") != -1 || phototype.indexOf("png") != -1){ 
					cloudinary.uploader.upload(path, function(result) {
						item_photo_name = constants.pool.escape('/' + result['public_id']);						
						uploadItem(request, response, item_photo_name);
					});
				}
				else{
					uploadItem(request, response, item_photo_name);					
				}		
			}
		}			
	}
	catch (error) {
		console.log((request.headers['x-forwarded-for'] || request.connection.remoteAddress) + " failed to upload a new item" );
		return response.json({
			"status": language.error_title,
			"message": language.error_unknownerror,
			"response": error
		});
	}
});

app.post('/edititem', bindToRequestBody, authentication, function(request, response) {
	function editItem(request, response, itemphotoname){
		var queryUpdateItem =
			"UPDATE items SET item_name = "+item_name+", item_desc = "+item_desc+", item_category = "+item_category+", item_photo = "+itemphotoname+" WHERE item_id = "+item_id+" AND item_ownerid = "+u_id+";";
		console.log("queryUpdateItem: " + queryUpdateItem);
		constants.pool.query(queryUpdateItem, function(errUpdateItem, rowsUpdateItem) {
			if (errUpdateItem) {
				console.log((request.headers['x-forwarded-for'] || request.connection.remoteAddress) + " failed to edit item" );
				return response.json({
					"status": language.error_title,
					"message": language.error_database,
					"response": errUpdateItem
				});
			}
			else {
				console.log(u_name + " successfully edited item with IP " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
				return response.json({
					"status": language.success_title,
					"message": language.success_edititem
				});
			}
		});
	}
	try {
		var body = request.body;	
		var u_name = request.body.username;
		console.log(u_name + " tries to edit item with IP " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
		var u_id = request.body.u_id;
		var item_id = constants.pool.escape(request.fields.item_id);
		if(null == body.item_name || "" == body.item_name){
			return response.json({
				"status": language.error_title,
				"message": language.error_itememptyitemname
			});
		}
		var item_name = constants.pool.escape(body.item_name);		
// 		if(null == body.item_desc || "" == body.item_desc){
// 			return response.json({
// 				"status": language.error_title,
// 				"message": language.error_itememptyitemdescription
// 			});
// 		}
		var item_desc = constants.pool.escape(body.item_desc);
		if(null == body.item_category || "" == body.item_category){
			return response.json({
				"status": language.error_title,
				"message": language.error_itememptyitemcategory
			});
		}
		var item_category = constants.pool.escape(body.item_category);
		var u_token = request.fields.u_token;
		var photo = request.files.photo;
		var item_editedphoto = constants.pool.escape(body.item_editedphoto);		
		if (null != photo && null == item_editedphoto) {
		//TODO yeni foto yükleme
			var phototype = request.files.photo.type;
			var path = constants.pool.escape(request.files.photo.path);
			if (null != phototype && null != path) {
				if (phototype.indexOf("jpeg") == -1 && phototype.indexOf("jpg") == -1 && phototype.indexOf("png") == -1 && phototype.indexOf("application/octet-stream") == -1) {
					console.log((request.headers['x-forwarded-for'] || request.connection.remoteAddress) + " failed to upload a new item" );
					response.json({
						"status": language.error_title,
						"message": language.error_filetype
					});
					return;
				}
				else {
					if (phototype.indexOf("jpeg") != -1 || phototype.indexOf("jpg") != -1 || phototype.indexOf("png") != -1){ 
						cloudinary.uploader.upload(path, function(result) {
							item_photo_name = constants.pool.escape('/' + result['public_id']);
							editItem(request, response, path);
						});
					}
					else{
						editItem(request, response, item_editedphoto);					
					}		
				}
			}			
		}
		else if(null != item_editedphoto){
			editItem(request, response, item_editedphoto);		
		}
	}
	catch (error) {
		console.log((request.headers['x-forwarded-for'] || request.connection.remoteAddress) + " failed to edit item" );
		return response.json({
			"status": language.error_title,
			"message": language.error_unknownerror,
			"response": error
		});
	}
});

app.post('/edituser', bindToRequestBody, authentication, function(request, response) {
	function editUser(request, response, queryUpdateUser){
		constants.pool.query(queryUpdateUser, function(errorUpdateUser, rowsUpdateUser) {
			if (errorUpdateUser) {
				console.log((request.headers['x-forwarded-for'] || request.connection.remoteAddress) + " failed to edit user" );
				return response.json({
					"status": language.error_title,
					"message": language.error_database,
					"response": errorUpdateUser
				});
			}
			else {
				console.log(u_name + " successfully edited user with IP " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));
				return response.json({
					"status": language.success_title,
					"message": language.success_edituser
				});
			}
		});
	}
	try {
		var u_name = request.body.username;
		console.log(u_name + " tries to edit user with IP " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));		
		var u_id = request.body.u_id;	
		var newuserlocation = constants.pool.escape(request.body.u_location);
		var newuserinfo = constants.pool.escape(request.body.u_info);
		var newusernotificationforbids = 0;
		if(null != request.body.u_notificationforbids){
			newusernotificationforbids = 1;
		}
		var newusernotificationformessages = 0;		
		if(null != request.body.u_notificationformessages){
			newusernotificationformessages = 1;
		}
		var u_photo = request.body.u_photo;
		var photo = request.files.photo;

		var ifValidPhotoUploaded = false;
		var imageType = request.files.photo.type;
		if (null != imageType) {
			if (imageType.indexOf("jpeg") != -1 || imageType.indexOf("jpg") != -1 || imageType.indexOf("png") != -1) {
				ifValidPhotoUploaded = true;
			}
		}
		
		if (ifValidPhotoUploaded) {
			var path = request.files.photo.path;
			cloudinary.uploader.upload(path, function(responseUpload) {
				if(responseUpload.error){
					return response.json({
						"status": language.error_title,
						"message": language.error_uploadphoto
					});
				}
				else{
					var user_photo_path = '/' + responseUpload['public_id'] + "." + responseUpload['format'];
					if (u_photo != constants.CLOUDINARY_ANON_USER_PHOTO) {
						var lindex = u_photo.lastIndexOf('/');
						var oldphoto = u_photo.substring(lindex + 1);
						if (oldphoto.indexOf("jpeg") !== -1) {
							var extensionold = ".jpeg";
						}
						else if (oldphoto.indexOf("jpg") !== -1) {
							var extensionold = ".jpg";
						}
						else if (oldphoto.indexOf("png") !== -1) {
							var extensionold = ".png";
						}
						var oldphoto = u_photo.substring(lindex + 1).replace(extensionold, "").replace("/","");
						cloudinary.uploader.destroy(oldphoto, function(responseDelete) {
							if (responseDelete.result != "ok") {
								console.log({
									"status": language.error_title,
									"message": language.error_editphoto,
									"response": responseDelete
								});
							}
							else {
								console.log({
									"status": language.success_title,
									"message": language.success_editphoto,
									"response": responseDelete								
								});
							}
						});
					}
					var queryUpdateUser = 
					"UPDATE users SET u_photo = '" + user_photo_path + "', u_location = " + newuserlocation + ", u_info = "+ newuserinfo +", u_notificationforbids = "+ newusernotificationforbids +", u_notificationformessages = "+ newusernotificationformessages +" WHERE u_id = '" + u_id + "'";
					editUser(request, response, queryUpdateUser);
				}					
			});
		}
		else {
			var queryUpdateUser = "UPDATE users SET u_location = " + newuserlocation + ", u_info = "+ newuserinfo +", u_notificationforbids = "+ newusernotificationforbids +", u_notificationformessages = "+ newusernotificationformessages +" WHERE u_id = '" + u_id + "'";
			editUser(request, response, queryUpdateUser);
		}
	}
	catch (error) {
		console.log(u_name + " successfully edited user with IP " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress));	
		response.json({
			"status": language.error_title,
			"message": language.error_unknownerror,
			"response": error
		});
	}
});
app.listen(app.get('port'), function() {
	console.log('Node app is running on port', app.get('port'));
});