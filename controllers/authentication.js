const jwt = require('jwt-simple');
const config = require('../config'); 
const User = require('../models/user'); 

function tokenForUser(user){
  const timestamp = new Date().getTime();
  return jwt.encode({ sub: user.id, iat: timestamp }, config.secret);
}

exports.signin = function(req,res,next){
    //user has had email and pw auth'd
  //now we gotta give them a token
   res.send( { token: tokenForUser(req.user) }); 
}

exports.signup = function(req,res,next){
  const email = req.body.email;
  const password= req.body.password;

  if(!email || !password){ 
    return res.status(422).send({ error: 'You must provide an email & pw'}); 
  }

  //see if user w email exists
  User.findOne({email:email}, function(err,existingUser){

    if(err) {return next(err) };

    //if user exists throw error
    if(existingUser){ 
      return res.status(422).send({ error: 'Email is already being used' }); 
    }

    //if user doenst exist create and save record
    const user = new User({
      email: email,
      password: password
    });

    user.save(function(err){
      if(err){return next(err)};

      //respond w record created
      res.json({ token: tokenForUser(user) }); 
    }); 

  });


}
