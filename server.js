const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const bodyParser = require("body-parser");
const session = require("express-session");
const jwt = require("jsonwebtoken");
const http = require("http");
const socketIo = require("socket.io");
const multer = require("multer");
const mime = require("mime-types");
const { log } = require("console");
const cloudinary = require("cloudinary").v2;
require("dotenv").config();

const app = express();
const server = http.createServer(app);
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });
const io = socketIo(server, {
  cors: {
    origin: "http://localhost:3000",
    methods: ["GET", "POST"],
    credentials: true,
  },
});

const PORT = 3001;
const saltRound = 10;
const secretKey = "yourSecretKey";

cloudinary.config({
  cloud_name: "dtgsps8aa",
  api_key: "699219159134714",
  api_secret: "NQQkZJLaF6mXTeIh316BAp3-bsU",
});

const connection = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "root",
  database: "sms",
});

connection.connect((err) => {
  if (err) {
    console.error("Error", err);
    return;
  }
  console.log("connected to database ");
});

app.use(
  cors({
    origin: "http://localhost:3000",
    methods: ["GET", "POST", "DELETE"],
    credentials: true,
  })
);
app.use(express.json());
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(
  session({
    key: "userId",
    secret: "subscribe",
    resave: false,
    saveUninitialized: false,
    cookie: {
      expires: 60 * 60 * 24,
    },
  })
);

const uidFieldSet = (mob, arr) => {
  const [village, mandal, district] = arr;
  return `${mob}.V${village}.M${mandal}.D${district}`;
};

app.post("/signup", upload.single("file"), (req, res) => {
  try {
    const {
      name,
      userName,
      password,
      mobileNumber,
      village,
      mandal,
      district,
    } = req.body;
    const file = req.file;

    if (
      !name ||
      !mobileNumber ||
      !userName ||
      !password ||
      !village ||
      !mandal ||
      !district ||
      !file
    ) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    bcrypt.hash(password, saltRound, (err, hash) => {
      if (err) {
        console.error("Error hashing password:", err);
        return res.status(500).json({ message: "Error hashing password" });
      }

      const checkUserQuery = `SELECT * FROM users WHERE role = 'user' AND (mobile_number = ? OR username = ?)`;
      const getVillageQuery = `SELECT village_id FROM villages WHERE village_name = ?`;
      const getMandalQuery = `SELECT mandal_id FROM mandals WHERE mandal_name = ?`;
      const getDistrictQuery = `SELECT district_id FROM districts WHERE district_name = ?`;
      const vilManDisArr = [];

      connection.query(
        checkUserQuery,
        [mobileNumber, userName],
        (err, results) => {
          if (err) {
            console.error("Error checking for existing user:", err);
            return res
              .status(500)
              .json({ message: "Error checking for existing user" });
          }

          if (results.length > 0) {
            return res.status(409).json({ message: "User already exists" });
          }

          // Proceed to get village, mandal, and district IDs
          connection.query(
            getVillageQuery,
            [village],
            (err, villageResults) => {
              if (err) {
                console.error("Error getting village ID:", err);
                return res
                  .status(500)
                  .json({ message: "Error getting village ID" });
              }
              vilManDisArr.push(villageResults[0].village_id);

              connection.query(
                getMandalQuery,
                [mandal],
                (err, mandalResults) => {
                  if (err) {
                    console.error("Error getting mandal ID:", err);
                    return res
                      .status(500)
                      .json({ message: "Error getting mandal ID" });
                  }
                  vilManDisArr.push(mandalResults[0].mandal_id);

                  connection.query(
                    getDistrictQuery,
                    [district],
                    (err, districtResults) => {
                      if (err) {
                        console.error("Error getting district ID:", err);
                        return res
                          .status(500)
                          .json({ message: "Error getting district ID" });
                      }
                      vilManDisArr.push(districtResults[0].district_id);
                      const uid = uidFieldSet(mobileNumber, vilManDisArr);
                      cloudinary.uploader
                        .upload_stream(
                          { folder: "your_folder_name" },
                          (error, result) => {
                            if (error) {
                              console.error("cloudinary upload error:", error);
                              return res
                                .status(500)
                                .send("Error uploading to cloudinary ");
                            }
                            const profilePicLink = result.secure_url;
                            // Insert the new user
                            const insertUserQuery = `INSERT INTO users(name, mobile_number, username, password, village, mandal, district, profile_pic,uid, role) VALUES (?, ?, ?, ?, ?, ?, ?, ?,?, 'user')`;
                            connection.execute(
                              insertUserQuery,
                              [
                                name,
                                mobileNumber,
                                userName,
                                hash,
                                village,
                                mandal,
                                district,
                                profilePicLink,
                                uid,
                              ],
                              (err, result) => {
                                if (err) {
                                  console.error(
                                    "Error creating the user:",
                                    err
                                  );
                                  return res.status(500).json({
                                    message: "Error creating the user",
                                  });
                                }
                                res.status(201).json({
                                  message: "User created successfully",
                                });
                              }
                            );
                          }
                        )
                        .end(req.file.buffer);
                    }
                  );
                }
              );
            }
          );
        }
      );
    });
  } catch (error) {
    console.error("Unexpected error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/login", (req, res) => {
  if (req.session.user) {
    res.send({ loggedIn: true, user: req.session.user });
  } else {
    res.send({ loggedIn: false });
  }
});

app.post("/login", (req, res) => {
  const { userName, password } = req.body;

  if (!userName || !password) {
    return res.status(400).json({ message: "missing required fields" });
  }

  const userLoginQuery =
    "SELECT username, password, role FROM users WHERE username = ?";
  connection.execute(userLoginQuery, [userName], (error, result) => {
    if (error) {
      return res.status(500).json({ message: "Internal server error" });
    }
    if (result.length === 0) {
      return res.status(404).json({ message: "User doesnot exists " });
    }
    const role = result[0].role;
    //if admin
    if (role === "admin") {
      const token = jwt.sign({ userName, role: "admin" }, secretKey, {
        expiresIn: "30m",
      });
      return res.json({ token });
    }

    //if user
    const hashedPassword = result[0].password;
    bcrypt.compare(password, hashedPassword, (error, isMatch) => {
      if (error) {
        return res.status(500).json({ message: "Internal server error" });
      }
      if (isMatch) {
        // req.session.user = result;
        const token = jwt.sign({ userName, role: "user" }, secretKey, {
          expiresIn: "30m",
        });
        return res.json({ token, message: "Login Successful" });
      } else {
        return res.status(401).json({ message: "invalid credentials" });
      }
    });
  });
});

app.get("/user_data/:username", (req, res) => {
  const { username } = req.params;
  const userSelectQuery = `SELECT * FROM users WHERE username = ?`;
  connection.execute(userSelectQuery, [username], (err, results) => {
    if (err) {
      return res.status(500).json({ message: "Error Retrieving User Details" });
    }
    if (results.length === 0) {
      return res.status(404).json({ message: "User Not Found" });
    }
    res.json(results[0]);
  });
});

app.get("/district-list", (req, res) => {
  const fetchDistrictsQuery = `SELECT * FROM districts`;
  connection.execute(fetchDistrictsQuery, (err, result) => {
    if (err) {
      return res.status(500).status({ message: "Internal server error" });
    }
    res.json(result);
  });
});

app.get("/mandal-list/:districtName", (req, res) => {
  const district = req.params.districtName;
  const fetchMandalsQuery = `SELECT DISTINCT(mandal) FROM users WHERE district = ?`;
  connection.execute(fetchMandalsQuery, [district], (err, results) => {
    if (err) {
      return res.status(500).json({ message: "Internal server error" });
    }
    res.json(results);
  });
});

app.get("/village-list/:mandalName", (req, res) => {
  const mandal = req.params.mandalName;
  const fetchVillageQuery = `SELECT DISTINCT(village) FROM users WHERE mandal = ?`;
  connection.execute(fetchVillageQuery, [mandal], (err, results) => {
    if (err) {
      return res.status(500).json({ message: "Internal server error" });
    }
    res.json(results);
  });
});

app.get("/user-list/:userName", (req, res) => {
  const user = req.params.userName;
  const fetchUserQuery = `SELECT * FROM users WHERE village = ?`;
  connection.execute(fetchUserQuery, [user], (err, results) => {
    if (err) {
      return res.status(500).json({ message: "Internal server error" });
    }
    res.json(results);
  });
});

app.post("/request-admin-access", upload.single("file"), (req, res) => {
  const {
    name,
    mobileNumber,
    age,
    village,
    mandal,
    district,
    state,
    requestFor,
  } = req.body;
  const date_and_time = new Date();

  const file = req.file;
  if (
    !name ||
    !mobileNumber ||
    !age ||
    !village ||
    !mandal ||
    !district ||
    !state ||
    !file
  ) {
    return res.status(400).json({ message: "Missing Required Fields" });
  }

  cloudinary.uploader
    .upload_stream({ folder: "your_folder_name" }, (error, result) => {
      if (error) {
        console.error("Cloudinary upload error:", error);
        return res
          .status(500)
          .json({ message: "Error uploading to Cloudinary" });
      }

      const fileData = result.secure_url;
      const insertRequestsQuery = `
      INSERT INTO accessadminrequests(name, mobile_number, age, village, mandal, district, state, photo, request_for, req_date_and_time, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
    `;

      connection.execute(
        insertRequestsQuery,
        [
          name,
          mobileNumber,
          age,
          village,
          mandal,
          district,
          state,
          fileData,
          requestFor,
          date_and_time,
        ],
        (err) => {
          if (err) {
            console.error("Database insertion error:", err);
            return res.status(500).json({ message: "Error Sending Request" });
          }
          return res.status(201).json({
            message: `Request sent to Admin for ${requestFor} Successfully`,
          });
        }
      );
    })
    .end(file.buffer);
});

app.get("/user-details/:i", (req, res) => {
  const userId = req.params.i;
  const fetchUsersQuery = `SELECT * FROM users WHERE user_id = ?`;
  connection.execute(fetchUsersQuery, [userId], (err, results) => {
    if (err) {
      return res.status(500).json({ message: "Error Fetching Users" });
    }

    const user = results[0];
    const profilePicBase64 = user.profile_pic.toString("base64");
    const mimeType = "image/jpeg"; // Adjust the MIME type if necessary
    user.profile_pic = `data:${mimeType};base64,${profilePicBase64}`;

    res.json(user);
  });
});

app.delete("/user-delete/:id", (req, res) => {
  const userId = req.params.id;
  const userDeleteQuery = `DELETE FROM users WHERE user_id = ?`;
  connection.execute(userDeleteQuery, [userId], (err, results) => {
    if (err) {
      return res.status(500).json({ message: "Internal server error" });
    }
    res.send({ message: "User deleted Successfully" });
  });
});

server.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
