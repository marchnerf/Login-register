const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const dotenv = require("dotenv");

dotenv.config();

const app = express();

app.use(express.json());

const DB_HOST = process.env.MYSQL_HOSTNAME;
const DB_USER = process.env.MYSQL_USERNAME;
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

const port = process.env.PORT || 3000;

app.listen(port, () => {
  console.log(`Server started on port ${port}...`);
});

app.post("/createUser", async (req, res) => {
  try {
    const user = req.body.username; 
    const password = req.body.password;

    const hashedPassword = await bcrypt.hash(password, 10);

    const connection = await pool.getConnection();

    try {
      const [existingUsers] = await connection.query(
        "SELECT * FROM users WHERE username = ?",
        [user]
      );

      if (existingUsers.length > 0) {
        connection.release();
        return res.status(409).json({ message: "User already exists" });
      }

      const [result] = await connection.query(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        [user, hashedPassword]
      );

      connection.release();

      res.status(201).json({ userId: result.insertId, message: "User created" });
    } catch (error) {
      connection.release();
      console.error("Error creating user:", error);
      res.status(500).json({ error: "Internal Server Error" });
    }
  } catch (error) {
    console.error("Error creating user:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});


