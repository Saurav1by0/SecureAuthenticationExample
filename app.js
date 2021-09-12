//jshint esversion:6
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
// const encrypt = require("mongoose-encryption");
// var sha512 = require('js-sha512');
// var bcrypt = require('bcryptjs');
// const salt = bcrypt.genSaltSync(10);
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const findOrCreate = require("mongoose-findorcreate");
const GoogleStrategy = require("passport-google-oauth20").Strategy;

// const  passport  = require('passport');
const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

app.use(
  session({
    secret: "Our Little Secret",
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", { useNewUrlParser: true });

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String,
});

userSchema.plugin(passportLocalMongoose);
// console.log(process.env.API_KEY);
userSchema.plugin(findOrCreate);
// userSchema.plugin(encrypt, { secret: process.env.SECRET , encryptedFields: ["password"] });

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());

passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
    },
    function (accessToken, refreshToken, profile, cb) {
      User.findOrCreate({ googleId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

app.get("/", function (req, res) {
  res.render("home");
});

app.route("/auth/google").get(
  passport.authenticate("google", {
    scope: ["profile"],
  })
);
app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  }
);
app.get("/login", function (req, res) {
  res.render("login");
});

app.get("/register", function (req, res) {
  res.render("register");
});

app.get("/secrets", function (req, res) {
//   res.set(
//     "Cache-Control",
//     "no-cache, private, no-store, must-revalidate, max-stal   e=0, post-check=0, pre-check=0"
//   );
//   if (req.isAuthenticated()) {
    User.find({ secret: { $ne: null } }, function (err, foundUsers) {
      if (err) {
        console.log(err);
      } else {
        if (foundUsers) {
          res.render("secrets", { usersWithSecrets: foundUsers });
        }
      }
    });
//   }
//  else {
//     res.redirect("/login");
//   }
});


app.get("/submit", function (req, res) {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});
app.post("/submit", function (req, res) {
  const submittedSecret = req.body.secret;
  console.log(req.user.id);
  User.findById(req.user.id, function (err, foundUser) {
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        foundUser.secret = submittedSecret;
        foundUser.save(function () {
          res.redirect("/secrets");
        });
      }
    }
  });
});
app.post("/register", function (req, res) {
  User.register(
    { username: req.body.username },
    req.body.password,
    function (err, user) {
      if (err) {
        console.log(err);
        res.redirect("/register");
      } else {
        passport.authenticate("local")(req, res, function () {
          res.redirect("/secrets");
        });
      }
    }
  );
});

// app.post("/register", function (req, res) {
// const hash = bcrypt.hashSync(req.body.password, salt);
// const newUser = new User({
//   email: req.body.username,
//   // password: sha512(req.body.password),
//   password :hash
// });
// newUser.save(function (err) {
//   if (err) {
//     console.log(err);
//   } else {
//     res.render("secrets");
//   }
// });
// });

// app.post("/login", function (req, res) {
// const hash = bcrypt.hashSync(req.body.password, salt);

// const username = req.body.username;
// // const password = sha512(req.body.password);
// const password = hash;

// User.findOne({ email: username }, function (err, foundUser) {
//   if (foundUser) {
//     if (bcrypt.compareSync(req.body.password, foundUser.password)) {
//       res.render("secrets");
//     } else if (foundUser.password != password) {
//       res.send("The password is incorrect.");
//     }
//   } else if (!foundUser) {
//     res.send("No registered user found.");
//   }
// });
// });

app.post("/login", passport.authenticate("local"), function (req, res) {
  res.redirect("/secrets");
});

app.get("/logout", (req, res) => {
  req.logout();
  req.session.destroy((err) => {
    if (!err) {
      res.status(200).clearCookie("connect.sid", { path: "/" }).redirect("/");
    } else {
      console.log(err);
    }
  });
});

app.listen(3000, function () {
  console.log("Server started on port 3000.");
});
