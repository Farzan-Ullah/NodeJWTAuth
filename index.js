const express = require("express");
const app = express();
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
dotenv.config();
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

//Authentication
const isLoggedIn = (req, res, next) => {
  try {
    const jwToken = req.headers.token;
    let userDetails = jwt.verify(jwToken, process.env.JWT_PRIVATE_KEY);
    if (!userDetails) throw new Error("You are not logged in");
    req.user = userDetails;
    next();
  } catch (error) {
    return res.json({
      message: "You're not logged in! Please login",
    });
  }
};

//Autorization
const isAdmin = (req, res, next) => {
  if (!req.user.isAdmin)
    return res.json({
      message: "You don't have access to this page",
    });

  next();
};

const isPremium = (req, res, next) => {
  if (!req.user.isPremium)
    return res.json({
      message: "You don't have access to this page!",
    });
  next();
};

app.use(cors());
app.use(bodyParser.urlencoded());
app.use(bodyParser.json());

const User = mongoose.model("User", {
  fullName: String,
  email: String,
  password: String,
  isAdmin: Boolean,
  isPremium: Boolean,
});

app.get("/", (req, res) => {
  res.send("New Express Server");
});

//Read (GET)
app.get("/users", async (req, res) => {
  try {
    const users = await User.find();
    res.json({
      status: "SUCCESS",
      data: users,
    });
  } catch (error) {
    res.status(500).json({
      status: "FAILED",
      message: "Something Went Wrong!",
    });
  }
});

app.post("/signup", async (req, res) => {
  const { fullName, email, password, isAdmin, isPremium } = req.body;
  try {
    const user = await User.findOne({ email });
    if (user) {
      return res.json({
        status: "User with this email exist. Please login",
      });
    }

    const encryptedPassword = await bcrypt.hash(password, 10);
    await User.create({
      fullName,
      email,
      password: encryptedPassword,
      isAdmin,
      isPremium,
    });
    res.json({
      status: "SUCCESS",
    });
  } catch (error) {
    res.status(500).json({
      status: "FAILED",
      message: "Something Went Wrong!",
    });
  }
});

//Create (POST)
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.json({
        status: "User with this email doesn`t exist. Please signup",
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch)
      res.json({
        status: "Login Failed!",
      });

    const jwToken = jwt.sign(user.toJSON(), process.env.JWT_PRIVATE_KEY, {
      expiresIn: 30,
    });
    return res.json({
      status: "Login Successful!",
      jwToken,
    });
  } catch (error) {
    res.status(500).json({
      status: "FAILED",
      message: "Something Went Wrong!",
    });
  }
});

//Private Routes
app.get("/profile", isLoggedIn, async (req, res) => {
  try {
    res.json({
      status: "PROFILE PAGE",
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({
      status: "FAILED",
      message: "Something Went Wrong!",
    });
  }
});

app.get("/admin/dashboard", isLoggedIn, isAdmin, async (req, res) => {
  try {
    res.json({
      status: "ADMIN DASHBOARD PAGE",
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({
      status: "FAILED",
      message: "Something Went Wrong!",
    });
  }
});

app.get("/premium", isLoggedIn, isPremium, async (req, res) => {
  try {
    res.json({
      status: "PREMIUM PAGE",
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({
      status: "FAILED",
      message: "Something went wrong!",
    });
  }
});

app.listen(process.env.PORT, () => {
  mongoose
    .connect(process.env.MONGODB_URL)
    .then(() => console.log("Server is up :)"))
    .catch((error) => console.log(error));
});
