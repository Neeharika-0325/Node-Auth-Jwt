var mongoose=require('mongoose');
var Schema=mongoose.Schema;
var bcrypt=require('bcrypt-nodejs'); //encrypted value using bcrypt

var UserSchema=new Schema({
    username:{
        type:String,
        unique:true,
        required:true
    },
    password:{
        type:String,
        required:true 
    }
});
// to make password to be encrypted, logic for generating encrypt password
UserSchema.pre('save',function(next){
    var user=this;
    if(this.isModified('password') || this.isNew){
        bcrypt.genSalt(10, function(err,salt){
            if(err){
                return next(err);
            }

            bcrypt.hash(user.password,salt,null,function (err,hash){
                if(err){
                    return next(err);
                }
                user.password=hash;

                next()
            })
        })
    }
    else{
        return next();
    }
})

UserSchema.method.comparePassword=function(passw,callback){
    bcrypt.compare(passw, this.password, function(err,isMatch){
        if(err){
            return callback(err);
        }cb(null,isMatch);
    })
}

module.exports=mongoose.model('user',UserSchema);