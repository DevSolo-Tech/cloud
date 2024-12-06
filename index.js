import express from "express";
import bodyParser from "body-parser";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import session from "express-session";
import mysql from "mysql2/promise";
import path from "path";
import axios from 'axios';


// Load environment variables
dotenv.config();

const PORT = 3000;
const app = express();

// MariaDB connection setup
const db = await mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});


// Cookie-based session middleware
app.use(
    session({
      secret: process.env.SESSION_SECRET,
      resave: false,
      saveUninitialized: false,
      cookie: {
        secure: false, // Set to true if using HTTPS in production
        maxAge: 24 * 60 * 60 * 1000, // 1 day
      },
    })
  );  

// Middleware setup
app.use(express.json());
app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));

//Get Route for home
app.get("/home", (req, res) => {
    res.render("index", {
      user: req.session.user || null, // Pass user info
      req: req, // Pass the request object
    });
  });
  

// Get Route For SignUP
app.get("/signup", (req, res) => {
    res.render("signup");
  });

  //Post Route for the SignUp Page
  app.post("/signup", async (req, res) => {
    const { fullname, email, password } = req.body;
  
    try {
      // Hash password
      const saltRounds = 10;
      const hashedPassword = await bcrypt.hash(password, saltRounds);
  
      // Insert user into database
      const query = `
        INSERT INTO users (fullname, email, password)
        VALUES (?, ?, ?)
      `;
  
      const [result] = await db.execute(query, [fullname, email, hashedPassword]);
  
      console.log(`User added with ID: ${result.insertId}`);
      res.redirect("/login"); // Redirect to login after successful signup
    } catch (error) {
      console.error("Error during signup:", error);
  
      if (error.code === "ER_DUP_ENTRY") {
        return res.status(400).send("Email is already registered.");
      }
  
      res.status(500).send("An error occurred. Please try again later.");
    }
  });
  

  // Get Route For Home
app.get("/login", (req, res) => {
    res.render("login");
  });

  app.post("/login", async (req, res) => {
    const { email, password } = req.body;
  
    try {
      // Fetch user from database
      const query = `SELECT * FROM users WHERE email = ?`;
      const [rows] = await db.execute(query, [email]);
  
      if (rows.length === 0) {
        return res.status(400).send("Invalid email or password.");
      }
  
      const user = rows[0];
  
      // Compare hashed password
      const passwordMatch = await bcrypt.compare(password, user.password);
      if (!passwordMatch) {
        return res.status(400).send("Invalid email or password.");
      }
  
      // Store user session
      req.session.user = {
        id: user.id,
        fullname: user.fullname,
        email: user.email,
      };
  
      console.log("User logged in:", req.session.user);
  
      res.redirect("/home"); // Redirect to home page after successful login
    } catch (error) {
      console.error("Error during login:", error);
      res.status(500).send("An error occurred. Please try again later.");
    }
  });


//Post Route for Logout
  app.post("/logout", (req, res) => {
    req.session.destroy((err) => {
        if (err) return res.redirect("/home");
        res.redirect("/login");
    });
});

// Fetch featured trailer
app.get("/api/featured-trailer", async (req, res) => {
  try {
    const [trailer] = await db.execute(
      "SELECT * FROM trailers ORDER BY created_at DESC LIMIT 1"
    );
    
    if (trailer.length === 0) {
      return res.status(404).json({ error: "No trailers found" });
    }
    
    res.json(trailer[0]);
  } catch (error) {
    console.error("Error fetching trailer:", error);
    res.status(500).json({ error: "Failed to fetch trailer" });
  }
});

// Fetch reviews for a trailer
app.get("/api/reviews/:trailerId", async (req, res) => {
  try {
    const [reviews] = await db.execute(
      `SELECT r.*, u.fullname 
       FROM reviews r 
       JOIN users u ON r.user_id = u.id 
       WHERE r.trailer_id = ? 
       ORDER BY r.created_at DESC`,
      [req.params.trailerId]
    );
    res.json(reviews);
  } catch (error) {
    console.error("Error fetching reviews:", error);
    res.status(500).json({ error: "Failed to fetch reviews" });
  }
});

// Add a review
app.post("/api/reviews", async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: "Must be logged in to post reviews" });
  }

  const { trailerId, review } = req.body;

  try {
    await db.execute(
      "INSERT INTO reviews (user_id, trailer_id, review) VALUES (?, ?, ?)",
      [req.session.user.id, trailerId, review]
    );
    res.json({ message: "Review added successfully" });
  } catch (error) {
    console.error("Error adding review:", error);
    res.status(500).json({ error: "Failed to add review" });
  }
});

// START THE SERVER
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });

