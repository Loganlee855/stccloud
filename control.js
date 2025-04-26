const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const router = express.Router();
const fs = require("fs");
const path = require("path");
require("dotenv").config();

const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
});

router.get("/", (req, res) => {
  let redirectUrl;

  if (req.session.auth) {
    redirectUrl = "/controls/app/dashboard";
  } else {
    redirectUrl = "/controls/app/login";
  }

  return res.redirect(redirectUrl);
});

const requireAppAuth = (req, res, next) => {
  const whiteList = ["/controls/app/login"];

  if (whiteList.indexOf(req.originalUrl) == -1) {
    if (!req.session.auth) {
      return res.redirect("/controls/app/login");
    }
  }

  next();
};

router.get("/login", (req, res) => {
  if (req.session.auth) {
    return res.redirect("/controls/app/dashboard");
  }

  return res.render("auth/login.ejs");
});

router.post("/api/auth/login", (req, res) => {
  try {
    const { username, password } = req.body;

    const query = "SELECT * FROM users WHERE username = ?";
    db.execute(query, [username], (err, results) => {
      if (err) {
        res.status(500).json({
          s: "f",
          m: "Internal Server error",
        });
      }

      if (results.length > 0) {
        const user = results[0];
        if (user.status != 1) {
          res.status(200).json({
            s: "f",
            m: "Account suspended",
          });
        }
        bcrypt.compare(password, user.password, (err, isMatch) => {
          if (err) {
            res.status(200).json({
              s: "f",
              m: "Invalid username or password",
            });
          }

          if (isMatch) {
            req.session.auth = user;
            res.status(200).json({
              s: "s",
              m: "Login Success",
            });
          } else {
            res.status(200).json({
              s: "f",
              m: "Invalid username or password",
            });
          }
        });
      } else {
        res.status(200).json({
          s: "f",
          m: "Invalid username or password",
        });
      }
    });
  } catch (error) {
    res.status(500).json({
      code: 500,
      message: "Internal Server error",
    });
  }
});

router.get('/auth/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.redirect("/controls/app/dashboard");
    }
    return res.redirect("/controls/app/login");
  });
});

router.get("/dashboard", requireAppAuth, (req, res) => {
  return res.render("dashboard.ejs", {
    session: req.session,
  });
});

router.get("/files", requireAppAuth, (req, res) => {
  return res.render("files.ejs", {
    session: req.session,
  });
});

router.post("/api/get_file_lists", requireAppAuth, (req, res) => {
  try {
    const query = "SELECT * FROM files ORDER BY createdAt DESC";
    db.query(query, (err, result) => {
      if (err) {
        return res.status(500).json({
          code: 999,
          message: "Internal Server Error",
        });
      }

      const data = result.map((fileRecord) => {
        const fileUrl = `${fileRecord.file_url}`;
        return {
          id: fileRecord.id,
          name: fileRecord.file_name,
          url: fileUrl,
          path: fileRecord.file_path,
          size: fileRecord.file_size,
          type: fileRecord.file_type,
          ip: fileRecord.client_ip,
          accessKey: fileRecord.accessKey,
          accessName: fileRecord.name,
          created_at: fileRecord.createdAt,
          updated_at: fileRecord.updatedAt,
        };
      });

      res.status(200).json({
        code: 200,
        message: "success",
        data,
      });
    });
  } catch (error) {
    res.status(500).json({
      code: 500,
      message: "Internal Server error",
    });
  }
});

router.post("/api/delete_file_lists/:id", (req, res) => {
  try {
    const fileId = req.params.id;
    const getQuery = "SELECT file_name, file_path FROM files WHERE id = ?";
    db.query(getQuery, [fileId], (err, result) => {
      if (err) {
        return res.status(500).json({
          s: 'f',
          m: "Internal Server Error",
        });
      }

      if (result.length === 0) {
        return res.status(200).json({
          s: 'f',
          m: "File not found",
        });
      }

      const fileName = result[0].file_name;
      const filePath = result[0].file_path;

      const fullPath = path.join(__dirname, "public", filePath);
      fs.unlink(fullPath, (err) => {
        if (err) {
          return res.status(500).json({
            s: 'f',
            m: "Internal Server Error",
          });
        }
        const deleteQuery = "DELETE FROM files WHERE id = ?";
        db.query(deleteQuery, [fileId], (err, result) => {
          if (err) {
            return res.status(500).json({
              s: 'f',
              m: "Internal Server Error",
            });
          }

          res.status(200).json({
            s: 's',
            m: `File deleted successfully!`,
            d: {
              file_name: fileName,
              file_path: filePath,
            },
          });
        });
      });
    });
  } catch (error) {
    return res.status(500).json({
      s: 'f',
      m: "Internal Server Error",
    });
  }
});

router.use((req, res) => {
  return res.render("layouts/404.ejs");
});

module.exports = router;
