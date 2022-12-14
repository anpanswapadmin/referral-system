/* Importing Different Modules */

const { globalVariables } = require("./config/config")
const express = require("express")
const mongoose = require("mongoose")
const path = require("path")
const hbs = require("express-handlebars")
const { mongoDbUrl, PORT } = require("./config/config")
const cookieParser = require('cookie-parser')
const logger = require('morgan')
const flash = require("connect-flash")
const session = require("express-session")
const MongoStore = require("connect-mongo")
const passport = require("passport")
const app = express()
const authRoutes = require("./app/routes/auth.routes")
const profileRoutes = require("./app/routes/profile.routes")
const apiAuthRoutes = require("./app/api/routes/auth.routes")

// Configure Mongoose to Connect to MongoDB
mongoose
  .connect(mongoDbUrl, {
    useNewUrlParser: true,
  })
  .then((response) => {
    console.log("MongoDB Connected Successfully.")
  })
  .catch((err) => {
    console.log("Database connection failed.")
  })

/* Configure express*/
app.use(express.json())
app.use(
  express.urlencoded({
    extended: true,
  })
)
app.use(cookieParser())
app.use(express.static(path.join(__dirname, "public")))

/*  Flash and Session*/
app.use(
  session({
    secret: "anysecret",
    store: MongoStore.create({ mongoUrl: 'mongodb://localhost:27017/referral-system' }),
    saveUninitialized: true,
    resave: true,
  })
)

app.get('/register/:refname', function (req, res) {
  req.session.ref = req.params.refname;
  res.redirect('/register');
})

app.use(flash())

/* Passport Initialize */
app.use(passport.initialize())
app.use(passport.session())

/* Use Global Variables */
app.use(globalVariables)

/* Setup View Engine To Use Handlebars */
app.engine(
  "handlebars",
  hbs({
    defaultLayout: "default",
  })
)
app.set('views', path.join(__dirname, 'views'))
app.set("view engine", "handlebars")

app.use(logger('dev'))

app.use("/", authRoutes)
app.use("/dashboard", profileRoutes)
app.use("/api", apiAuthRoutes)

/* Start The Server */
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`)
})
