const express = require("express");
const crypto = require('crypto');
const mysql = require("mysql2");
const axios = require("axios");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const fileType = require("file-type");
const fileUpload = require("express-fileupload");
const { v4: uuidv4 } = require("uuid");
const currentDate = new Date();
const rateLimit = require("express-rate-limit");
const xml2js = require("xml2js");
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const controlRouter = require("./control");
require('dotenv').config();
const session = require("express-session");
const MySQLStore = require("express-mysql-session")(session);
const compression = require("compression");
const cookieParser = require("cookie-parser");
const authSchema = require("./validations/auth");

const app = express();
const port = process.env.PORT || 5010;
app.disable('x-powered-by');
app.use(cors({ origin: "*" }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(fileUpload());
app.use(express.static(path.join(__dirname, 'public')));
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");
app.engine("html", require("ejs").renderFile);

app.use(compression());
app.use(cookieParser());

const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
});

function executeQuery(query, params) {
  return new Promise((resolve, reject) => {
    db.execute(query, params, (err, results) => {
      if (err) reject(err);
      resolve(results);
    });
  });
}

const sessionStore = new MySQLStore({}, db)

app.use(
  session({
    key: "_gid",
    cookie: {
      path: "/",
      httpOnly: true,
    },
    secret: process.env.SECRET_KEY || "secretKey",
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
  })
);


const apiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 999999999999999,
  message: "Too many requests from this IP, please try again after 15 minutes.",
});

app.use("/controls",(req, res, next) => {
  res.removeHeader('Content-Security-Policy');
  next();
});


app.use("/api/", apiLimiter);
app.use("/controls/app", controlRouter);

function generateMD5(string) {
  const year = currentDate.getFullYear();
  const month = String(currentDate.getMonth() + 1).padStart(2, "0");
  const day = String(currentDate.getDate()).padStart(2, "0");
  const sha1 = crypto.createHash('sha1').update(string + `${year}${month}${day}`).digest('hex');
  return crypto.createHash('sha256').update(sha1).digest('hex');
}

function generateRandomString(length) {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    const randomByte = crypto.randomBytes(1);
    const randomIndex = randomByte[0] % characters.length;
    result += characters[randomIndex];
  }
  return result;
}

const isBackdoorFile = async (filePath) => {
  const buffer = fs.readFileSync(filePath);
  const shellPatterns = [
    "phpinfo()",
    "<?php",
    "eval",
    "base64_decode",
    "exec",
    "system",
  ];

  for (let pattern of shellPatterns) {
    if (buffer.toString().includes(pattern)) {
      return true;
    }
  }

  return false;
};

app.post("/api/image/v1/upload", async (req, res) => {
  try {
    if (!req.body || !req.body.accessKey) {
      return res.status(403).json({
        code: 403,
        message: "Invalid accessKey",
      });
    } else if (!req.body || !req.body.secretKey) {
      return res.status(403).json({
        code: 403,
        message: "Invalid secretKey",
      });
    } else if (!req.files || !req.files.file) {
      return res.status(500).json({
        code: 999,
        message: "Internal Server Error",
      });
    }

    const apiQuery = 'SELECT * FROM users WHERE accessKey = ? AND secretKey = ? AND status = ?';
    const resultsx = await executeQuery(apiQuery, [req.body.accessKey, req.body.secretKey,1]);

    if (resultsx.length === 0) {
      return res.status(403).json({
        code: 403,
        message: "Invalid credentials",
      });
    }

    const file = req.files.file;
    const folder = req.body && req.body.folder ? req.body.folder : 'ImageFile';
    const filesName = req.body && req.body.fileName ? req.body.fileName + path.extname(file.name) : uuidv4().replace(/-/g, "") + path.extname(file.name);
    const filePath = path.join(__dirname, 'public', folder, filesName);
    const fileType = file.mimetype;
    const fileSize = file.size;

    if (!fs.existsSync(path.join(__dirname, 'public', folder))) {
      fs.mkdirSync(path.join(__dirname, 'public', folder), { recursive: true });
    }

    file.mv(filePath, async (err) => {
      if (err) {
        return res.status(500).json(err);
      }

      const hasBackdoor = await isBackdoorFile(filePath);
      if (hasBackdoor) {
        fs.unlinkSync(filePath);
        return res.status(500).json({
          code: 999,
          message: "File type is not allowed",
        });
      }

      const fileUrl = `${req.protocol}://${req.get("host")}/${folder}/${filesName}`;
      const updest = `/${folder}/${filesName}`;
      const clientIp = req.ip || req.connection.remoteAddress;
      const requestUrl = req.originalUrl;
      const uuid = uuidv4();

      const query = "INSERT INTO files (id,file_name,file_path, file_url, file_type, file_size, client_ip, request_url,accessKey,name) VALUES (?,?, ?, ?, ?, ?, ?, ?, ?, ?)";
      const values = [uuid,filesName,updest, fileUrl, fileType, fileSize, clientIp, requestUrl,resultsx[0].accessKey,resultsx[0].name];

      await executeQuery(query, values);

      res.json({
        code: 200,
        message: "File uploaded successfully!",
        data: {
          id: uuid,
          path: updest,
          name: filesName,
          url: fileUrl,
          size: fileSize,
          type: fileType,
        }
      });
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      code: 999,
      message: "Internal Server Error",
    });
  }
});

app.post("/api/image/v2/upload", async (req, res) => {
  try {
    const { file } = req.body;
    if (!req.body || !req.body.accessKey) {
      return res.status(403).json({
        code: 403,
        message: "Invalid accessKey",
      });
    } else if (!req.body || !req.body.secretKey) {
      return res.status(403).json({
        code: 403,
        message: "Invalid secretKey",
      });
    } else if (!file) {
      return res.status(500).json({
        code: 999,
        message: "Internal Server Error",
      });
    }

    const apiQuery = 'SELECT * FROM users WHERE accessKey = ? AND secretKey = ? AND status = ?';
    const resultsx = await executeQuery(apiQuery, [req.body.accessKey, req.body.secretKey, 1]);

    if (resultsx.length === 0) {
      return res.status(403).json({
        code: 403,
        message: "Invalid credentials",
      });
    }

    const response = await axios({
      url: file,
      responseType: "stream",
    });
    const fileSize = response.headers['content-length'];
    if (!fileSize) {
      return res.status(400).json({
        code: 400,
        message: "File size could not be determined.",
      });
    }

    const extname = path.extname(file);
    const folder = req.body && req.body.folder ? req.body.folder : 'ImageFile';
    const filesName = req.body && req.body.fileName ? "ggtwxx" + req.body.fileName + extname : uuidv4().replace(/-/g, "") + extname;
    const filePath = path.join(__dirname, 'public', folder, filesName);

    if (!fs.existsSync(path.join(__dirname, 'public', folder))) {
      fs.mkdirSync(path.join(__dirname, 'public', folder), { recursive: true });
    }

    const writer = fs.createWriteStream(filePath);
    response.data.pipe(writer);

    writer.on("finish", async () => {
      const hasBackdoor = await isBackdoorFile(filePath);
      if (hasBackdoor) {
        fs.unlinkSync(filePath);
        return res.status(500).json({
          code: 999,
          message: "File type is not allowed",
        });
      }

      const fileUrl = `${req.protocol}://${req.get("host")}/${folder}/${filesName}`;
      const updest = `/${folder}/${filesName}`;
      const clientIp = req.ip || req.connection.remoteAddress;
      const requestUrl = req.originalUrl;
      const uuid = uuidv4();
      const query = "INSERT INTO files (id, file_name, file_path, file_url, file_type, file_size, client_ip, request_url, accessKey, name) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
      const values = [uuid, filesName, updest, fileUrl, response.headers['content-type'], fileSize, clientIp, requestUrl, resultsx[0].accessKey, resultsx[0].name];
      await executeQuery(query, values);
      res.json({
        code: 200,
        message: "File uploaded successfully!",
        data: {
          id: uuid,
          path: updest,
          name: filesName,
          url: fileUrl,
          size: fileSize,
          type: response.headers['content-type'],
        },
      });
    });

    writer.on("error", (err) => {
      return res.status(500).json({
        code: 999,
        message: "Internal Server Error",
      });
    });
  } catch (error) {
    return res.status(500).json({
      code: 999,
      message: "Internal Server Error",
    });
  }
});


app.post("/api/image/v1/delete/:id", async (req, res) => {
  try {
    if (!req.body || !req.body.accessKey) {
      return res.status(403).json({
        code: 403,
        message: "Invalid accessKey",
      });
    } else if (!req.body || !req.body.secretKey) {
      return res.status(403).json({
        code: 403,
        message: "Invalid secretKey",
      });
    }


    const apiQuery = 'SELECT * FROM users WHERE accessKey = ? AND secretKey = ? AND status = ?';
    const resultsx = await executeQuery(apiQuery, [req.body.accessKey, req.body.secretKey,1]);

    if (resultsx.length === 0) {
      return res.status(403).json({
        code: 403,
        message: "Invalid credentials",
      });
    }

    const fileId = req.params.id;
    const getQuery = "SELECT file_name, file_path FROM files WHERE id = ?";
    db.query(getQuery, [fileId], (err, result) => {
      if (err) {
        return res.status(500).json({
          code: 999,
          message: "Internal Server Error",
        });
      }

      if (result.length === 0) {
        return res.json({
          code: 200,
          message: "File not found",
        });
      }

      const fileName = result[0].file_name;
      const filePath = result[0].file_path;

      const fullPath = path.join(__dirname, "public", filePath);
      fs.unlink(fullPath, (err) => {
        if (err) {
          return res.status(500).json({
            code: 999,
            message: "Internal Server Error",
          });
        }
        const deleteQuery = "DELETE FROM files WHERE id = ?";
        db.query(deleteQuery, [fileId], (err, result) => {
          if (err) {
            return res.status(500).json({
              code: 999,
              message: "Internal Server Error",
            });
          }

          res.json({
            code: 200,
            message: `File with ${fileName} deleted successfully!`,
            data: {
              file_name: fileName,
              file_path: filePath,
            },
          });
        });
      });
    });
  } catch (error) {
    return res.status(500).json({
      code: 999,
      message: "Internal Server Error",
    });
  }
});


app.post("/api/image/v1/files", async (req, res) => {
try {

  if (!req.body || !req.body.accessKey) {
    return res.status(403).json({
      code: 403,
      message: "Invalid accessKey",
    });
  } else if (!req.body || !req.body.secretKey) {
    return res.status(403).json({
      code: 403,
      message: "Invalid secretKey",
    });
  }


  const apiQuery = 'SELECT * FROM users WHERE accessKey = ? AND secretKey = ? AND status = ?';
  const resultsx = await executeQuery(apiQuery, [req.body.accessKey, req.body.secretKey,1]);

  if (resultsx.length === 0) {
    return res.status(403).json({
      code: 403,
      message: "Invalid credentials",
    });
  }

  const folderPath = path.join(__dirname, "public");
  fs.readdir(folderPath, (err, files) => {
    if (err) {
      return res.status(500).json({
        code: 999,
        message: "Internal Server Error",
      });
    }

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
          request_url: fileRecord.request_url,
          created_at: fileRecord.createdAt,
          updated_at: fileRecord.updatedAt,
        };
      });

      res.json({
        code: 200,
        message: "success",
        data,
      });
    });
  });
} catch (error) {
  return res.status(500).json({
    code: 999,
    message: "Internal Server Error",
  });
}
});

app.use('/api/image',(req, res, next) => {
  res.status(404).json({
    code: 404,
    message: `Not found`,
  });
});

app.use((req, res, next) => {
  const rstring = generateRandomString(16);
  const hostId = crypto
    .createHash("sha512")
    .update(uuidv4())
    .digest("base64");

    const errorResponse = {
      Code: "AccessDenied",
      Message: "Access Denied",
      RequestId: rstring,
      HostId: hostId,
    };

    const builder = new xml2js.Builder({
      rootName: 'Error',
      headless: true,
      renderOpts: { pretty: false, indent: '  ', newline: '\n' }
    });

    let xml = builder.buildObject(errorResponse);

    xml = `<?xml version="1.0" encoding="UTF-8"?>\n` + xml;
  
    res.set('Content-Type', 'application/xml');
    res.status(404).send(xml);
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
