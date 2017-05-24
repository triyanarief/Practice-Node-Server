const User = require('../models/user');
const passport = require('passport');
const config = require('../config');
const JwtStrategy = require('passport-jwt').Strategy; 
const ExtractJwt = require('passport-jwt').ExtractJwt; 
const LocalStrategy = require('passport-local'); 

//setup options for local strategy
const localOptions={ usernameField: 'email'  }

//create Local Strategy
const localLogin = new LocalStrategy(localOptions, function(email, password,done){
  //verify email and pw, call done w this user
  //if correct
  //otherwise call done w false
  User.findOne({ email: email }, function(err, user) {
    if(err) {return done(err); }

    if(!user){return done(null, false);}

    // compare passwords - is 'password' equal to user.password ?
    // gotta compare plain text pw to encrcypted pw
    user.comparePassword(password, function(err,isMatch){ 
      if (err) { return done(err); }
      if (!isMatch){ return done(null, false); }

      return done(null, user); 
    }); 
  }); 
}); 

//setup options for JWT Strategy
const jwtOptions= {
  jwtFromRequest: ExtractJwt.fromHeader('authorization'),
  secretOrKey: config.secret
}; 

//create JWT Strategy
const jwtLogin = new JwtStrategy(jwtOptions, function(payload, done){
  User.findById(payload.sub, function(err,user){
    if(err) {return done(err,false); }

    if(user){
      done(null, user);
    } else {
      done(null, false); 
    }

  }); 
});

//tell passport to use this strategy
passport.use(jwtLogin); 
passport.use(localLogin); 
