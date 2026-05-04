const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo").default;
const bcrypt = require("bcrypt");
const Joi = require("joi");
require("dotenv").config();

const app = express();
const port = process.env.PORT || 3000;
const saltRounds = 12;

// Session expires after 1 hour (in milliseconds)
const expireTime = 1 * 60 * 60 * 1000;

// MongoDB connection info from .env file
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

// Connect to MongoDB
const { MongoClient } = require("mongodb");
const atlasURI = `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/?retryWrites=true`;
var database = new MongoClient(atlasURI);
const userCollection = database.db(mongodb_database).collection("users");

// Tell express to parse form data
app.use(express.urlencoded({ extended: false }));

// Set up sessions stored in MongoDB
var mongoStore = new MongoStore({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
  crypto: { secret: mongodb_session_secret },
});

app.use(
  session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true,
    cookie: { maxAge: expireTime },
  })
);

// Serve images from the public folder
app.use(express.static("public"));

// ---------- ROUTES ----------

// Home page
app.get("/", (req, res) => {
  if (!req.session.authenticated) {
    res.send(`
      <h1>Welcome</h1>
      <button onclick="location.href='/signup'">Sign up</button>
      <br><br>
      <button onclick="location.href='/login'">Log in</button>
    `);
  } else {
    res.send(`
      <h1>Hello, ${req.session.name}!</h1>
      <button onclick="location.href='/members'">Go to Members Area</button>
      <br><br>
      <button onclick="location.href='/logout'">Logout</button>
    `);
  }
});

// Sign up page
app.get("/signup", (req, res) => {
  res.send(`
    <h2>create user</h2>
    <form action="/signupSubmit" method="post">
      <input name="name" placeholder="name" /><br>
      <input name="email" placeholder="email" /><br>
      <input name="password" type="password" placeholder="password" /><br>
      <button type="submit">Submit</button>
    </form>
  `);
});

// Sign up form submission
app.post("/signupSubmit", async (req, res) => {
  const name = req.body.name;
  const email = req.body.email;
  const password = req.body.password;

  // Validate inputs with Joi
  const schema = Joi.object({
    name: Joi.string().max(50).required(),
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required(),
  });

  const validationResult = schema.validate({ name, email, password });
  if (validationResult.error != null) {
    const message = validationResult.error.details[0].message;
    res.send(`
      <p>${message}</p>
      <a href="/signup">Try again</a>
    `);
    return;
  }

  // Hash the password
  const hashedPassword = await bcrypt.hash(password, saltRounds);

  // Save user to database
  await userCollection.insertOne({ name, email, password: hashedPassword });

  // Create session and send to members
  req.session.authenticated = true;
  req.session.name = name;
  req.session.cookie.maxAge = expireTime;
  res.redirect("/members");
});

// Login page
app.get("/login", (req, res) => {
  res.send(`
    <h2>log in</h2>
    <form action="/loginSubmit" method="post">
      <input name="email" placeholder="email" /><br>
      <input name="password" type="password" placeholder="password" /><br>
      <button type="submit">Submit</button>
    </form>
  `);
});

// Login form submission
app.post("/loginSubmit", async (req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  // Validate inputs with Joi
  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required(),
  });

  const validationResult = schema.validate({ email, password });
  if (validationResult.error != null) {
    res.send(`
      <p>Invalid email/password combination.</p>
      <a href="/login">Try again</a>
    `);
    return;
  }

  // Look up user in database
  const result = await userCollection
    .find({ email: email })
    .project({ name: 1, email: 1, password: 1 })
    .toArray();

  if (result.length != 1) {
    res.send(`
      <p>Invalid email/password combination.</p>
      <a href="/login">Try again</a>
    `);
    return;
  }

  // Check password
  if (await bcrypt.compare(password, result[0].password)) {
    req.session.authenticated = true;
    req.session.name = result[0].name;
    req.session.cookie.maxAge = expireTime;
    res.redirect("/members");
  } else {
    res.send(`
      <p>Invalid email/password combination.</p>
      <a href="/login">Try again</a>
    `);
  }
});

// Members page
app.get("/members", (req, res) => {
  if (!req.session.authenticated) {
    res.redirect("/");
    return;
  }

  const images = ["cat1.jpg", "cat2.jpg", "cat3.jpg"];
  const randomImage = images[Math.floor(Math.random() * images.length)];

  res.send(`
    <h1>Hello, ${req.session.name}.</h1>
    <img src="${randomImage}" width="300" /><br><br>
    <button onclick="location.href='/logout'">Sign out</button>
  `);
});

// Logout
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

// 404 page - must be last!
app.get("*splat", (req, res) => {
  res.status(404).send("<h1>Page not found - 404</h1>");
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});