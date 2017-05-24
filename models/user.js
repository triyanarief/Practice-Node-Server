const mongoose = require('mongoose'); 
const Schema = mongoose.Schema;
const bcrypt = require('bcrypt-nodejs'); 
const SALT_WORK_FACTOR = 10;

const userSchema = new Schema({
  email: {type: String, unique: true, lowercase: true},
  password: String
});

// on Save Hook, encrypt pw 
userSchema.pre('save', function(next) {
  var user = this;

  // only hash the password if it has been modified (or is new)
  if (!user.isModified('password')) return next();

  // generate a salt
  bcrypt.genSalt(SALT_WORK_FACTOR, function(err, salt) {
    if (err) return next(err);

    // hash the password using our new salt
    bcrypt.hash(user.password, salt,null,  function(err, hash) {
      if (err) return next(err);

      // override the cleartext password with the hashed one
      user.password = hash;
      next();
    });
  });
});

userSchema.methods.comparePassword = function(candidatePassword,callback){
  bcrypt.compare(candidatePassword, this.password, function(err, isMatch){
    if(err){ return callback(err); }

    callback(null, isMatch); 
  }); 
}

const ModelClass = mongoose.model('user', userSchema); 

module.exports = ModelClass; 
