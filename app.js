require('dotenv').config(); 
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");  //decleare it above passport
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose"); //plugin
const GoogleStrategy = require( 'passport-google-oauth2' ).Strategy; 
const findOrCreate = require('mongoose-findorcreate');

const app = express();
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public")); 

//place app.use(session) right below app.use(express) and above mongoose.connect
//KEEP ORDER IN WHICH SESSION AND PASSPORT ARE INITIALIZED IN THE SAME ORDER AS THINGS ARE INTER-DEPENDENT
app.use(session({
    secret: "MySecretKey",
    resave: false,
    saveUninitialized: false //Choosing false is useful for implementing login sessions, reducing server storage usage, or complying with laws that require permission before setting a cookie.
}));

//This method passport.initialize() comes bundled with passport
app.use(passport.initialize());
app.use(passport.session());  //Using passport to manage our sessions

mongoose.connect("mongodb://localhost:27017/userDB");

//Adding new keyword makes it an object of mongoose Schema class. Without it const userSchema = {...} is a plain JS Object
//You should have at least one field in your Schema
const userSchema = new mongoose.Schema({
    email: String,
    googleId: String,
    secret: String
    // password: {
    //     type: String,
    //     required: [true, "Password is an essential field"]
    // }
});

//When using passport-local-mongoose, the 'username' and 'password' field in the schema is not required. The plugin automatically adds the 'username' and 'password' field to the schema and handles the password hashing and management internally.

//to hash and salt our passwords, and to save our user data in MongoDB 
userSchema.plugin(passportLocalMongoose);
//to enable the functioning of findOrCreate, adding this plugin to our Schema
userSchema.plugin(findOrCreate);

const User = mongoose.model('userGoogle', userSchema);   //Model: userGoogle

passport.use(User.createStrategy());

//Passport-Local Configuration (Limited to Local Strategy)
//serializing a user object into a format that can be stored in a session.
// passport.serializeUser(User.serializeUser());        //creating cookie  
// passport.deserializeUser(User.deserializeUser());   //destroying cookie

passport.serializeUser(function(user, cb) {  //cb: callback function
  process.nextTick(function() {
    //null indicates no error during serialisation (converting user object in a format that can be stored in a session)
    return cb(null, {  
      id: user.id,
    //   email: user.email,
      username: user.username,
      picture: user.picture,
    });
  });
});

passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  });
});

passport.use(new GoogleStrategy({
    clientID:   process.env.CLIENT_ID,  //help Google recognise our Web App
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:7000/auth/google/secrets",
    userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo',
    passReqToCallback: true
  },
  function(request, accessToken, refreshToken, profile, done) {  //callback func. where user sends back an Access token, profile contains email and other info that Google is giving us access to
    User.findOrCreate({ username: profile.displayName, email: profile.email, googleId: profile.id }, function (err, user) {
    //   console.log(profile);
      return done(err, user);
    });
  }
));


app.get("/", (req, res)=>{
    res.render("home");
});

app.get("/login", (req, res)=>{
    res.render("login", {message: ""});
});

app.post("/login", (req, res)=>{ //Checking for username and password
    const newUser = new User ({
        email: req.body.username,
        username: req.body.username,
        password: req.body.password
    });

    req.login(newUser, function(err){
        if(err) {
            console.log(err);
            res.redirect("/login");
        } else {
            passport.authenticate("local")(req, res, function(){  //cookie generation for authentication
                res.redirect("/secrets");
            });  //=> Client has been authenticated successfully and cookie has been created on the local client side system
        }
    });
});

app.get("/register", (req, res)=>{
    res.render("register", {message: ""});
});

app.post("/register", (req,res)=>{
    //Using passport-local-mongoose as a mailman to handle creation of a new user, saving their password, and authenticating them. Basically, Registering a user. It salts and hash the password automatically using below code:
    //username and password fields added by passport.js
    User.register({email: req.body.username, username: req.body.username},  req.body.password, function(err, user) {  
        if (err) {
            console.log(err);   
            res.redirect("/register");
        } else {
            //Authenticating user locally using Passport and creating the cookie
            passport.authenticate("local")(req, res, function(){ 
                //callback triggered only if authentication is successful, cookie is created and current logged in session of the user is saved. 
                res.redirect("/secrets");
                //If user managed to be here, it means Authentication has already been performed, cookie created for session. We can redirect instead of just rendering the secrets ejs file unlike in encryption and hashing case
            })
        }
    });
});

app.get("/secrets", function(req, res){
    //Not checking is user is authenticated here as we allow everyone to read through secrets
    view();
    async function view(){
        const found = await User.find({"secret": {$ne: null}}); //finding fields whose 'secret' key is not equal (ne) to null
        // (await found).forEach(function(user){
        //         console.log(user.secret);
        // })
        res.render("secrets", {secretArr: found});
    }
});
 
app.get("/logout", (req,res)=>{ 
    req.logout(function(err) {   //passport.js method that expires the session and deletes the cookie
        if (err) console.log(err); 
    });  
    res.redirect("/");
});

app.get("/auth/google", (req,res)=>{
    //authenticating with Google strategy instead of "local" as before by redirecting to Google Authentication page
    passport.authenticate("google", { scope: ['email', 'profile'] })(req, res)
});

app.get("/auth/google/secrets",
    passport.authenticate( "google", {
        successRedirect: "/secrets",
        failureRedirect: "/login"
}));

app.get("/submit", (req,res)=>{
    if(req.isAuthenticated()){  //If user is authenticated already, allowing them to submit a secret
        res.render("submit");
    } else res.redirect("/login");
});

app.post("/submit", (req,res)=>{
    const secret = req.body.secret;
    // console.log(req.user);
    add();
    async function add(){
        const found = await User.findById(req.user.id);
        if(found) {
            found.secret = secret;
            found.save();
            res.redirect("/secrets");
        } else
            redirect("/login");
    }
});

app.listen(7000, function(){
    console.log("Server listening on Port 7000");
});


// <%for(int i=0; i<usersWithSecrets.length; ++i){   %>
//       <p class="secret-text"><%= usersWithSecrets[0].secret %></p>
//     <% }; %>