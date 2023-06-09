// passport jwt :-authentication middleware for nodejs environment


var JwtStrategy=require('passport-jwt').Strategy;
var ExtractJwt=require('passport-jwt').Strategy;

var User=require('../models/user');
var config=require('../config/db');

module.exports=function(passport){
    var opts={};
    opts.jwtFromRequest=ExtractJwt.fromAuthHeader(); //pick jwt token from header
    opts.secretOrKey=config.secret;
    passport.use(new JwtStrategy(opts,function(jwt_payload, done){
        User.findOne({id:jwt_payload.id}, function(err,user){
            if(err){
                return done(err,false);
            }
            if(user){
                done(null,user);
            }else{
                done(null,false);
            }
        })
    }))
}