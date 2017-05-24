const Authentication = require('./controllers/authentication'); 
const passportService = require('./services/passport');
const passport = require('passport'); 

const requireAuth = passport.authenticate('jwt', { session: false}); 
const requireSignin = passport.authenticate('local', {session: false}); 

module.exports = function(app){
  app.get('/', requireAuth, function(req,res){
    res.send({ hi: "there"  });
  });
  // for anything posted to /signup
  // we wanna run Auth.signup
  app.post('/signup', Authentication.signup);

  //signin
  app.post('/signin', requireSignin, Authentication.signin); 
}
