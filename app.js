//jshint esversion:6
require('dotenv').config();     //håller hemligheter hemliga
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const flash = require('express-flash')
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const rateLimit = require('express-rate-limit');

const MongoClient = require('mongodb').MongoClient;

const auditLog = require('audit-log');
const app = express();
const https = require('https');
const http = require('http');//testmiljö
const fs = require("fs");
const initializePassport = require('./passport-config')

//audit log i mongoDB, loggar user aktivitet 
auditLog.addTransport("mongoose", {connectionString: "mongodb://localhost/auditdb"})


const PORT = process.env.PORT || 3000
const uri = process.env.MONGODB;

//Cerificate ,hemliga nycklar till SSL/TSL, som tillåter hemlig kommunikation mellan server och browser
const options = {
    key: fs.readFileSync('elizabeths-key.pem'),
    cert: fs.readFileSync('elizabeths-cert.pem')
}; 
//Monitorering länkar till healthcheck route, övvervakar appen mot attacker
app.use('/healthcheck', require('./routes/healthcheck.routes'));

app.use(express.static('public')); //css filen ligger här
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended: true
}));

//cookies som lagras i session storage
app.use(session({
    secret:process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: true }
}));

app.use(passport.initialize()); //passport startar kryptering
app.use(passport.session());   //passport startar cookies
//cookies slutar


//connection till Mogno DB via defaultport.
//om user registrerar sig Google kan vi bara se Google ID and submitted Secret
//om user registrerar via login ser vi username, krypterat password and secret   
mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true});
//mongoose.set("useCreateIndex", true); behövs ej längre Mongoose 6


//structur för vårt document, krypterar databasen med hjälp av plugin
const userSchema = new mongoose.Schema ({
    email: String,
    password: String,
    googleId: String, //struktur för vårt document, krypterar databasen med hjälp av plugin genom google, och skapar inte ny id varje gång i DB
    secret: String
});
//kryptering
userSchema.plugin(passportLocalMongoose);  //krypterar (när man anropar save plugin) , saltar och hashar automatiskt åt oss
userSchema.plugin(findOrCreate);  //dekrypterar (när man anropar find plugin) , hittar avändare genom google id eller skapar om user inte finns

const User = new mongoose.model("User", userSchema);//skapar användare i DB


//Autentisering
passport.use(User.createStrategy());//autentiserar användaren


//serialize skapar krypterad cookie med personens id, funkar för alla strategies
passport.serializeUser(function(user, done){
    done(null, user.id)
});
 //deserialize tar sönder cookie så vi kan identifiera personen
passport.deserializeUser(function (id, done) {
    User.findById(id, function(err, user){
        done(err, user);
    });
});

//kryptering , passport google Oauth 2, autentiserar user med new google strategy
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID, //hemlig ID från google dev ,länkar till .env
    clientSecret: process.env.CLIENT_SECRET, //hemlig client secret från google dev ,länkar till .env
    callbackURL: "http://localhost:3000/auth/google/secretapp",//hjälper google att känna igen vår app, callback för att slutföra auth
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"//hjälper google att känna igen vår app
}, //hämtar info från userinfo inte google+ account
  

//Auktorisering , google skickar accesstoken så att vi kan använda data så länge det behövs
  function(accessToken, refreshToken, profile, cb) { //cd = callback
      console.log(profile)
//installera paket mongoose findOrCreate, skapar el hittar id och profil genom googleid
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


//Acesslogging , begränsar login försök till 10ggr under 15 min, loggar antal försök från samma IP adress
const createLimiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 minutes/h, millisek
	max: 10, //10 försök
	message: "Too many accounts created from this IP, please try again after 15 minutes",//meddelande som visas
    standardHeaders: true,//visar hur många ggr du har kvar att logga in
	legacyHeaders: false,
});

const limiter = rateLimit({ //skickar olika meddelanden i olika sidor
	windowMs: 15 * 60 * 1000,
	max: 10,
	message: "Too many requests sent from this IP, please try again after 15 minutes",
    standardHeaders: true, 
	legacyHeaders: false, 
});

/* 
### ALLA ROUTES ###
*/ 

app.get('/' , function(req,res){
    res.render('home')
});

//passport auth med google strategy, popup ruta för att user ska logga in
app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile'] })//scope limiterar kapacitet av token, mindre power till hackare
);


//google skickar tbx user, autentiserar user lokalt och blir hänvisad till appens secrets
app.get('/auth/google/secretapp', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/secrets');
  });

//blockar för många försök i login och register routes
app.get('/login',limiter, function(req,res){
    res.render('login')
});

app.get('/register',createLimiter, function(req,res){
    res.render('register')
});

//länkar till terms and conditions sida med text
app.get('/terms', function(req, res){
    res.render('terms') //Skickar användaren till Terms
});

//hittar alla secrets som blir inskickade
app.get('/secrets', function (req, res){
    User.find({'secret': {$ne: null}}, function(err, foundUsers){
        if(err){
            console.log(err)
        } else {
            if(foundUsers) {
                res.render('secrets', {usersWithSecrets: foundUsers});
            }
        }
    });
});

//skicka in en secret, om dom inte är inloggade skickas dom till login först
app.get('/submit', function (req,res) {
    if(req.isAuthenticated()){
        res.render('submit')
    }else {
        res.redirect('/login');
    }
});

//secret blir inskickad, findById gör så att secret hamnar på rätt id
//när user blir aut, sparas info i req.user.id
//om samma user loggar in igen så lagras deras secret på deras id
//console.log(req.user.id);
app.post('/submit', function(req, res) {
    const submittedSecret = req.body.secret;
     //hittar en specifik user genom ID
    User.findById(req.user.id, function(err, foundUser){
        if (err) {
            console.log(err)
        } else {
            if(foundUser) {
                foundUser.secret = submittedSecret;
                foundUser.save(function(){
                    res.redirect('/secrets');
                });
            }
            auditLog.logEvent(user.username, 'maybe script name or function',
            "tried to log in", 'the affected target name perhaps', 'target id', 'additional info, JSON, etc.');
        }
    });
});

//loggar ut användare avslutar session/cookies
app.get('/logout', function(req, res, next) {
    req.logout();
      req.session = null; //tar bort cookie
      res.redirect('/');
  });

//om login lyckas kommer user in till secrets , annars blir user kvar på register
//registrerar nya anändare med passport med local strategy
app.post('/register',(req,res)=>{
 
    User.register({username: req.body.username}, req.body.password, function(err, user){
        if(err){
            console.log(err);
            res.redirect('/register');
        } else {
            passport.authenticate('local')(req, res, function(){
                res.redirect('/login');
            });
        }
    });
});
//kollar så att username och password matchar med passport
app.post('/login', function(req, res){
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });
    auditLog.logEvent(user.username, 'maybe script name or function',
    "tried to log in", 'the affected target name perhaps', 'target id', 'additional info, JSON, etc.');//auditlog funkade bara i denna function eftersom det är en post
    
    req.login(user, function(err){
        if(err){
            console.log(err);
            res.redirect('/login');
        } else{
            passport.authenticate('local')(req, res, function(){
                res.redirect('/secrets');
            });
        }
    });
});


//Acesslogging , Touring Test, recaptcha ser till att du inte är en robot
//räknar även antal försök till login 
function recaptcha_callback() {
    var loginBtn = document.querySelector('#login-btn');
    loginBtn.removeAttribute('disabled');
    loginBtn.style.cursor = 'pointer';
}



/*
app.listen(PORT, () =>  {
    console.log('info', `STARTED LISTENING ON PORT ${PORT}`);
});

*/
http.createServer(app).listen(PORT, function(){
  console.log('info', `STARTED LISTENING ON PORT ${PORT}`);
});

https.createServer(options, app).listen(443, function(){
  console.log('HTTPS listening on 443');
});
