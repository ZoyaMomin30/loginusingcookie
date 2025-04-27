import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport, { strategies } from "passport";
import { Strategy } from "passport-local";

const app = express();
const port = 3000;
const saltRounds = 10;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
  secret:"SESSIONTRIAL",
  resave:false,   //this is set to false because not connected to db. if we want to restart the server and still be able to see the db we need to see express-session with db store so even if we restart the server the credentials will be saved in database
  saveUninitialized:true, 
  cookie:{
    maxAge: 1000 * 60 * 60 * 24,//age of the cookie is one day
  },
  })
);

//it is important to have declared the above lines before the using the middleware(lines of code below)

app.use(passport.initialize())
app.use(passport.session())

const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "secrets",
  password: "1234",
  port: 5432,
});
db.connect();

app.get("/", (req, res) => {
  console.log(req.user)
  if (req.isAuthenticated()){
    res.render("secrets.ejs") //if true show then the secrets 
  } else{
    res.render("home.ejs")   //if not then redirect to login
  }
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/secrets",(req, res) => {
  //.isAuthenticated() is from passport. it allows us to check is the current user whos logged in in the current session is authenticated already. 
  console.log(req.user)
  if (req.isAuthenticated()){
    res.render("secrets.ejs") //if true show then the secrets 
  } else{
    res.redirect("/login ")   //if not then redirect to login
  }
});

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      res.send("Email already exists. Try logging in.");
    } else {
      //hashing the password and saving it in the database
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          console.log("Hashed Password:", hash);
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [email, hash]
          );
          const user = result.rows[0];
          req.login(user, (err)=> {
            console.log(err)
            res.redirect("/secrets")
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

app.post("/login",passport.authenticate("local", {
  successRedirect:"/secrets",
  failureRedirect:"/login" 
}));

passport.use(new Strategy(async function verify (username, password, cb){
  //trying to validate whether if a user already has the right password, is it registered in the database
  try {
    const result = await db.query("SELECT * FROM users WHERE email = $1", [
      username,
    ]);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      const storedHashedPassword = user.password;
      bcrypt.compare(password, storedHashedPassword, (err, result) => {
        if (err) {
          return cb(err);
        } else {
          if (result) {
            return cb(null, user);
          } else {
            return cb (null, false );
          }
        }
      });
    } else {
      return cb("User not found");
    }
  } catch (err) {
    return cb(err);
  }
}));

passport.serializeUser((user, cb) => {
  cb(null,user);
});

passport.deserializeUser((user, cb) => {
  cb(null,user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});