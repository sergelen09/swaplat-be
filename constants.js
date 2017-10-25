var warnings = require('./warnings');
var language = new warnings.Turkish();

const SITE_KEY = process.env.SITE_KEY;
exports.SITE_KEY = SITE_KEY;
const SECRET_KEY = process.env.SECRET_KEY;
exports.SECRET_KEY = SECRET_KEY;
const ENCRYPTION_KEY_TOKEN = process.env.ENCRYPTION_KEY_TOKEN;
exports.ENCRYPTION_KEY_TOKEN = ENCRYPTION_KEY_TOKEN;
const ENCRYPTION_KEY_FORGOTPASSWORD = process.env.ENCRYPTION_KEY_FORGOTPASSWORD;
exports.ENCRYPTION_KEY_FORGOTPASSWORD = ENCRYPTION_KEY_FORGOTPASSWORD;
const ENCRYPTION_KEY_REMEMBERPASSWORD = process.env.ENCRYPTION_KEY_REMEMBERPASSWORD;
exports.ENCRYPTION_KEY_REMEMBERPASSWORD = ENCRYPTION_KEY_REMEMBERPASSWORD;
const CLOUDINARY_ANON_USER_PHOTO = "/anonymous_userphoto";
exports.CLOUDINARY_ANON_USER_PHOTO = CLOUDINARY_ANON_USER_PHOTO;
const CLOUDINARY_ANON_ITEM_PHOTO = "/anonymous_itemphoto";
exports.CLOUDINARY_ANON_ITEM_PHOTO = CLOUDINARY_ANON_ITEM_PHOTO;
const MESSAGE_ENCRYPTION_KEY = process.env.MESSAGE_ENCRYPTION_KEY;
exports.MESSAGE_ENCRYPTION_KEY = MESSAGE_ENCRYPTION_KEY;
const api_directory = process.env.API_DIRECTORY;
exports.api_directory = api_directory;
const photo_directory = process.env.PHOTO_DIRECTORY;
const photo_directory_10 =	photo_directory + "fl_progressive:semi,q_10";
exports.photo_directory_10 = photo_directory_10;								
const photo_directory_50 = photo_directory + "fl_progressive:semi,q_50";			
exports.photo_directory_50 = photo_directory_50;								
const photo_directory_100 = photo_directory + "fl_progressive:semi,q_100";
exports.photo_directory_100 = photo_directory_100;								
const host_directory =	process.env.HOST_DIRECTORY;
exports.host_directory = host_directory;								

const nodemailer = require('nodemailer');
// create reusable transporter object using the default SMTP transport
var transporter = nodemailer.createTransport({
	host: 'sub5.mail.dreamhost.com',
	auth: {
		user: 'support@swaplat.com',
		pass: process.env.SUPPORTEMAIL_PASSWORD
	}
});
exports.transporter = transporter;

const mysql = require('mysql');
var pool = mysql.createPool({
	connectionLimit: 20,
	host: process.env.DB_HOST,
	user: process.env.DB_USER,
	password: process.env.DB_PASSWORD,
	database: process.env.DB_NAME,
	port: process.env.DB_PORT,
	debug: false
});
exports.pool = pool;

const RateLimit = require('express-rate-limit');
var limiter = new RateLimit({
	windowMs: 15 * 60 * 1000, // 15 minutes 
	max: 100, // limit each IP to 100 requests per windowMs 
	delayMs: 0 // disable delaying - full speed until the max limit is reached 
});
exports.limiter = limiter;

exports.Redirect = function (request, response, next) {
	var originHost = request.get('origin'); 
	console.log(originHost + " host isminden " + (request.headers['x-forwarded-for'] || request.connection.remoteAddress) + " ile baglanti istegi yapildi");
	
	if(originHost == "https://swaplat.com" || originHost == "http://localhost:8888"){
		if (request.secure) {
			 // request was via https, so do no special handling
			 next();
		} 
		else {
			 // request was via http, so redirect to https
			 response.redirect('https://' + request.headers.host + request.url);
		}
	}
	else
	{
		return response.json({
			"status": language.error_title,
			"message": language.error_undefinedhostname
		});
	} 
}