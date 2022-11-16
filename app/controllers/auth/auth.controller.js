const bcrypt = require("bcryptjs")
const User = require("../../models/user").User
const Referral = require("../../models/referral").Referral
const ReferralService = require("../../services/referral.service")
const { v4: uuidv4 } = require("uuid")
const passport = require('passport')
let LocalStrategy = require('passport-local').Strategy;

passport.serializeUser(function(user, done){
	done(null, user.id)
})

passport.deserializeUser(function(id, done){
	User.findById(id, function(err, user){
		done(err, user)
	})
})

//Local strategy
passport.use(new LocalStrategy(
  function(username, password, done) {
    userData.findOne({ username: username}, function (err, user) {
      if (err) { 
          return done(err); 
        }
      if (!user) { 
      	return done(null, false); 
      }
      userData.comparePassword(password, user.password, (err, isMatch)=>{
		if(err) throw err
		if(isMatch){
            console.log(user)
			return done(null, user)
		}else{
			return done(null, false, {message: 'Invalid Password'})
		}
	})
    });
  }
));

module.exports = {
  /* LOGIN ROUTES */
  getLoginPage: (req, res) => {
    res.render("default/login", { message: req.flash("error") })
  },

  /* REGISTER ROUTES*/
  getRegisterPage: async (req, res) => {
    //Checks if register link contains query "reflink"
    if (req.query.reflink > "") {
      //Validate referral link and gets the referrer
      const referral = await ReferralService.checkReferer({
        referralLink: req.query.reflink,
      })
      res.render("default/register")
      //Sends  a flash message of the referrer
      req.flash(
        "success-message",
        "You were referred by " + referral.userId.fullname
      )
    } else {
      res.render("default/register")
    }
  },

  registerUser: async (req, res, next) => {
    let errors = []

    if (!req.body.fullname) {
      errors.push({ message: "Fullname is mandatory" })
    }
    if (!req.body.email) {
      errors.push({ message: "Email field is mandatory" })
    }
    if (!req.body.password) {
      errors.push({ message: "Password field is mandatory" })
    }
    //Checks if there are errors in registering a user
    if (errors.length > 0) {
      res.render("default/register", {
        errors: errors,
        fullname: req.body.fullname,
        email: req.body.email,
      })
    } else {
      await User.findOne({ email: req.body.email }).then((user) => {
        //Checks if user already exists in the database and redirect to login
        if (user) {
          req.flash("error-message", "Email already exists, try to login.")
          res.redirect("/login")
        } else {
          const { fullname, email, password } = req.body
          const referrala = req.session.ref
          //Creates new user
          const newUser = new User({
            fullname: fullname,
            email: email,
            password: password,
            referred: referrala,
          })
          //Generate SALT with 10 rounds
          bcrypt.genSalt(10, (err, salt) => {
            //Hash pzssword before saving to database
            bcrypt.hash(newUser.password, salt, (err, hash) => {
              newUser.password = hash
              //Save user to database
              newUser.save().then((user) => {
                //Creates new referral for new user
                const newReferrer = new Referral({
                  referralId: uuidv4(),
                  referralLink: uuidv4(),
                  userId: user._id,
                })
                //save referral to the database and redirect to login
                newReferrer.save()
                req.flash("success-message", "You are now registered")
                res.redirect("/login")
              })
            })
          })
        }
      })
    }
  },
}
