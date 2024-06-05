const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const dotenv = require("dotenv");
const ejs = require("ejs");
const path = require("path");
const bodyParser = require("body-parser");
const session = require("express-session");

dotenv.config();

const app = express();

app.use(express.json());
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "web"));
app.use("/web", express.static(path.join(__dirname, "web")));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(
  session({
    secret: "your-secret-key",
    resave: false,
    saveUninitialized: true,
  })
);

const DB_HOST = process.env.MYSQL_HOSTNAME;
const DB_USER = process.env.MYSQL_USER;
const DB_PASSWORD = process.env.MYSQL_PASSWORD;
const DB_DATABASE = process.env.MYSQL_DB;
const DB_PORT = process.env.MYSQL_PORT;

const pool = mysql.createPool({
  host: DB_HOST,
  user: DB_USER,
  password: DB_PASSWORD,
  database: DB_DATABASE,
  port: DB_PORT,
  connectionLimit: 100,
});

const port = process.env.PORT || 8000;

app.listen(port, () => {
  console.log(`Server started on port ${port}...`);
});

app.get("/", (req, res) => {
  if (req.session.user) {
    res.render("index");
  } else {
    res.redirect("/login");
  }
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/register", (req, res) => {
  const user = req.body.username;
  const password = req.body.password;

  bcrypt.hash(password, 10, (hashErr, hashedPassword) => {
    if (hashErr) {
      console.error("Error hashing password:", hashErr);
      res.status(500).json({ error: "Internal Server Error" });
      return;
    }

    pool.getConnection((connErr, connection) => {
      if (connErr) {
        console.error("Error getting database connection:", connErr);
        res.status(500).json({ error: "Internal Server Error" });
        return;
      }

      connection.query(
        "SELECT * FROM users WHERE username = ?",
        [user],
        (selectErr, existingUsers) => {
          if (selectErr) {
            connection.release();
            console.error("Error selecting user:", selectErr);
            res.status(500).json({ error: "Internal Server Error" });
            return;
          }

          if (existingUsers.length > 0) {
            connection.release();
            res.render("register", { error: "User already exists!!!" });
          } else {
            connection.query(
              "INSERT INTO users (username, password) VALUES (?, ?)",
              [user, hashedPassword],
              (insertErr, result) => {
                connection.release();
                if (insertErr) {
                  console.error("Error creating user:", insertErr);
                  res.status(500).json({ error: "Internal Server Error" });
                } else {
                  console.log("Register Successful");
                  req.session.user = user;
                  pool.query("UPDATE users SET is_active = 1 WHERE username = ?", [user], (updateErr) => {
                    if (updateErr) {
                      console.error("Error updating active status:", updateErr);
                    }
                  });
                  res.redirect("/");
                }
              }
            );
          }
        }
      );
    });
  });
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  pool.getConnection((connErr, connection) => {
    if (connErr) {
      console.error("Error getting database connection:", connErr);
      res.status(500).json({ error: "Internal Server Error" });
      return;
    }

    const sqlSearch = "SELECT * FROM users WHERE username = ?";
    const search_query = mysql.format(sqlSearch, [username]);

    connection.query(search_query, async (err, result) => {
      connection.release();

      if (err) {
        console.error(err);
        res.status(500).json({ error: "Internal Server Error" });
        return;
      }

      if (result.length === 0) {
        console.log("User does not exist");
        res.render("login", { error: "User does not exist, please register first." });
      } else {
        const hashedPassword = result[0].password;

        bcrypt.compare(password, hashedPassword, (bcryptErr, isPasswordMatch) => {
          if (bcryptErr) {
            console.error(bcryptErr);
            res.status(500).json({ error: "Internal Server Error" });
          } else if (isPasswordMatch) {
            console.log("Login Successful");
            req.session.user = username;
            pool.query("UPDATE users SET is_active = 1 WHERE username = ?", [username], (updateErr) => {
              if (updateErr) {
                console.error("Error updating active status:", updateErr);
              }
              res.redirect("/");
            });
          } else {
            console.log("Password Incorrect");
            res.render("login", { error: "Password incorrect!!!" });
          }
        });
      }
    });
  });
});

app.post("/logout", (req, res) => {
  const username = req.session.user;
  req.session.destroy((err) => {
    if (err) {
      console.error("Error destroying session:", err);
      res.status(500).json({ error: "Internal Server Error" });
    } else {
      pool.query("UPDATE users SET is_active = 0 WHERE username = ?", [username], (updateErr) => {
        if (updateErr) {
          console.error("Error updating active status:", updateErr);
        }
        console.log("Logout Successful");
        res.redirect("/login");
      });
    }
  });
});
