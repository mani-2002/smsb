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
const cloudinary = require("cloudinary").v2;
require("dotenv").config();

const app = express();
const server = http.createServer(app);
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

const PORT = process.env.PORT || 3001;
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
    console.error("Error connecting to the database", err);
    return;
  }
  console.log("Connected to the database");
});

app.use(
  cors({
    origin: ["http://localhost:3000", "https://smsf.vercel.app"],
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
    secret: secretKey,
    resave: false,
    saveUninitialized: false,
    cookie: {
      expires: 60 * 60 * 24 * 1000,
    },
  })
);

const uidFieldSet = (mob, arr) => {
  const [village, mandal, district] = arr;
  return `${mob}.V${village}.M${mandal}.D${district}`;
};

app.post("/signup", upload.single("file"), async (req, res) => {
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

    const hash = await bcrypt.hash(password, saltRound);

    const checkUserQuery = `SELECT * FROM users WHERE role = 'user' AND (mobile_number = ? OR username = ?)`;
    const getVillageQuery = `SELECT village_id FROM villages WHERE village_name = ?`;
    const getMandalQuery = `SELECT mandal_id FROM mandals WHERE mandal_name = ?`;
    const getDistrictQuery = `SELECT district_id FROM districts WHERE district_name = ?`;

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

        connection.query(getVillageQuery, [village], (err, villageResults) => {
          if (err) {
            console.error("Error getting village ID:", err);
            return res
              .status(500)
              .json({ message: "Error getting village ID" });
          }
          const villageId = villageResults[0].village_id;

          connection.query(getMandalQuery, [mandal], (err, mandalResults) => {
            if (err) {
              console.error("Error getting mandal ID:", err);
              return res
                .status(500)
                .json({ message: "Error getting mandal ID" });
            }
            const mandalId = mandalResults[0].mandal_id;

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
                const districtId = districtResults[0].district_id;
                const uid = uidFieldSet(mobileNumber, [
                  villageId,
                  mandalId,
                  districtId,
                ]);

                cloudinary.uploader
                  .upload_stream(
                    { folder: "your_folder_name" },
                    (error, result) => {
                      if (error) {
                        console.error("Cloudinary upload error:", error);
                        return res
                          .status(500)
                          .json({ message: "Error uploading to Cloudinary" });
                      }

                      const profilePicLink = result.secure_url;

                      const insertUserQuery = `INSERT INTO users(name, mobile_number, username, password, village, mandal, district, profile_pic, uid, role) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'user')`;

                      connection.query(
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
                        (err) => {
                          if (err) {
                            console.error("Error creating the user:", err);
                            return res
                              .status(500)
                              .json({ message: "Error creating the user" });
                          }
                          res
                            .status(201)
                            .json({ message: "User created successfully" });
                        }
                      );
                    }
                  )
                  .end(req.file.buffer);
              }
            );
          });
        });
      }
    );
  } catch (error) {
    console.error("Unexpected error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/login", (req, res) => {
  if (req.session.user) {
    res.json({ loggedIn: true, user: req.session.user });
  } else {
    res.json({ loggedIn: false });
  }
});

app.post("/login", (req, res) => {
  const { userName, password } = req.body;

  if (!userName || !password) {
    return res.status(400).json({ message: "Missing required fields" });
  }

  const userLoginQuery =
    "SELECT username, password, role FROM users WHERE username = ?";
  connection.query(userLoginQuery, [userName], (error, result) => {
    if (error) {
      return res.status(500).json({ message: "Internal server error" });
    }
    if (result.length === 0) {
      return res.status(404).json({ message: "User does not exist" });
    }

    const hashedPassword = result[0].password;
    bcrypt.compare(password, hashedPassword, (error, isMatch) => {
      if (error) {
        return res.status(500).json({ message: "Internal server error" });
      }
      if (isMatch) {
        const role = result[0].role;
        const token = jwt.sign({ userName, role }, secretKey, {
          expiresIn: "30m",
        });
        return res.json({ token, role, message: "Login Successful" });
      } else {
        return res.status(401).json({ message: "Invalid credentials" });
      }
    });
  });
});

app.get("/user_data/:username", (req, res) => {
  const { username } = req.params;
  const userSelectQuery = `SELECT * FROM users WHERE username = ?`;
  connection.query(userSelectQuery, [username], (err, results) => {
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
  connection.query(fetchDistrictsQuery, (err, result) => {
    if (err) {
      return res.status(500).json({ message: "Internal server error" });
    }
    res.json(result);
  });
});

app.get("/mandal-list/:districtName", (req, res) => {
  const district = req.params.districtName;
  const fetchMandalsQuery = `SELECT DISTINCT(mandal) FROM users WHERE district = ?`;
  connection.query(fetchMandalsQuery, [district], (err, results) => {
    if (err) {
      return res.status(500).json({ message: "Internal server error" });
    }
    res.json(results);
  });
});

app.get("/village-list/:mandalName", (req, res) => {
  const mandal = req.params.mandalName;
  const fetchVillageQuery = `SELECT DISTINCT(village) FROM users WHERE mandal = ?`;
  connection.query(fetchVillageQuery, [mandal], (err, results) => {
    if (err) {
      return res.status(500).json({ message: "Internal server error" });
    }
    res.json(results);
  });
});

app.get("/user-list/:userName", (req, res) => {
  const user = req.params.userName;
  const fetchUserQuery = `SELECT * FROM users WHERE village = ? AND role = 'user'`;
  connection.query(fetchUserQuery, [user], (err, results) => {
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
      let insertRequestsQuery;
      if (requestFor === "District Admin Access") {
        insertRequestsQuery = `
          INSERT INTO accessadminrequests(name, mobile_number, age, village, mandal, district, state, photo, request_for, req_date_and_time, status,tag)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending','S')
        `;
      } else if (requestFor === "Mandal Admin Access") {
        insertRequestsQuery = `
          INSERT INTO accessadminrequests(name, mobile_number, age, village, mandal, district, state, photo, request_for, req_date_and_time, status,tag)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending','D')
        `;
      } else {
        insertRequestsQuery = `
          INSERT INTO accessadminrequests(name, mobile_number, age, village, mandal, district, state, photo, request_for, req_date_and_time, status,tag)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending','M')
        `;
      }

      connection.query(
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
    .end(req.file.buffer);
});

app.get("/requests-for-admin-access", (req, res) => {
  const fetchRequestsQuery = `SELECT * FROM accessadminrequests WHERE tag = 'S' ORDER BY req_date_and_time DESC`;
  connection.query(fetchRequestsQuery, (err, result) => {
    if (err) {
      return res.status(500).json({ message: "internal server error" });
    }
    res.json(result);
  });
});

app.get("/requests-for-mandal-admin-access", (req, res) => {
  const fetchMandalAdminAccessRequestsQuery = `SELECT * FROM accessadminrequests WHERE tag = 'D' ORDER BY req_date_and_time DESC`;
  connection.query(fetchMandalAdminAccessRequestsQuery, (err, result) => {
    if (err) {
      return res.status(500).json({ message: "internal server error" });
    }
    res.json(result);
  });
});

app.get("/user-details/:i", (req, res) => {
  const userId = req.params.i;
  const fetchUsersQuery = `SELECT * FROM users WHERE user_id = ?`;
  connection.query(fetchUsersQuery, [userId], (err, results) => {
    if (err) {
      return res.status(500).json({ message: "Error Fetching Users" });
    }
    res.json(results[0]);
  });
});

app.delete("/user-delete/:id", (req, res) => {
  const userId = req.params.id;
  const userDeleteQuery = `DELETE FROM users WHERE user_id = ?`;
  connection.query(userDeleteQuery, [userId], (err) => {
    if (err) {
      return res.status(500).json({ message: "Internal server error" });
    }
    res.json({ message: "User deleted Successfully" });
  });
});

app.delete("/delete-request/:id", async (req, res) => {
  const requestId = req.params.id;
  try {
    connection.query("DELETE FROM accessadminrequests WHERE request_id = ?", [
      requestId,
    ]);
    res.status(200).json({ message: "Request deleted successfully" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

const createUserNameAndPasswordForAdmins = (role, mobileNumber) => {
  const username = `${role}-${mobileNumber.slice(-4)}`;
  const password = `${role}${mobileNumber.slice(-4)}`;
  return { username, password };
};

app.post("/accept-request/:id", (req, res) => {
  const requestId = req.params.id;
  const fetchRequestQuery = `SELECT * FROM accessadminrequests WHERE request_id = ?`;
  connection.execute(fetchRequestQuery, [requestId], async (err, result) => {
    if (err) {
      return res.status(500).json({ message: "internal server error" });
    }
    const name = result[0].name;
    const mobileNumber = result[0].mobile_number;
    const village = result[0].village;
    const mandal = result[0].mandal;
    const district = result[0].district;
    const profilePic = result[0].photo;
    if (result[0].request_for === "District Admin Access") {
      const arr = [];
      const dis = result[0].district;
      const fetchDistrictIdQuery = `SELECT district_id FROM districts WHERE district_name = ?`;
      const role = "dadmin";
      const { username, password } = createUserNameAndPasswordForAdmins(
        role,
        mobileNumber
      );
      const hash = await bcrypt.hash(password, saltRound);
      connection.execute(fetchDistrictIdQuery, [dis], (err, result) => {
        arr.push(result[0].district_id);
        const uid = `D${arr[0]}`;
        const districtAdminInsertQuery = `INSERT INTO users (name,mobile_number,username,password,village,mandal,district,profile_pic,uid,role) VALUES(?,?,?,?,?,?,?,?,?,?)`;
        connection.execute(
          districtAdminInsertQuery,
          [
            name,
            mobileNumber,
            username,
            hash,
            village,
            mandal,
            district,
            profilePic,
            uid,
            role,
          ],
          (err, result) => {
            if (err) {
              return res.status(500).json({ message: "internal server error" });
            }
            return res
              .status(201)
              .json({ message: "District Admin Created Successfully" });
          }
        );
      });
    } else if (result[0].request_for === "Mandal Admin Access") {
      const arr = [];
      const man = result[0].mandal;
      const dis = result[0].district;
      const fetchMandalIdQuery = `SELECT mandal_id FROM mandals WHERE mandal_name = ?`;
      const role = "madmin";
      const { username, password } = createUserNameAndPasswordForAdmins(
        role,
        mobileNumber
      );
      const hash = await bcrypt.hash(password, saltRound);
      connection.execute(fetchMandalIdQuery, [man], (err, result) => {
        arr.push(result[0].mandal_id);
        const fetchDistrictIdQuery = `SELECT district_id FROM districts WHERE district_name = ?`;
        connection.execute(fetchDistrictIdQuery, [dis], (err, result) => {
          arr.push(result[0].district_id);
          const uid = `M${arr[0]}D${arr[1]}`;
          const mandalAdminInsertQuery = `INSERT INTO users (name,mobile_number,username,password,village,mandal,district,profile_pic,uid,role) VALUES(?,?,?,?,?,?,?,?,?,?)`;
          connection.execute(
            mandalAdminInsertQuery,
            [
              name,
              mobileNumber,
              username,
              hash,
              village,
              mandal,
              district,
              profilePic,
              uid,
              role,
            ],
            (err, result) => {
              if (err) {
                return res
                  .status(500)
                  .json({ message: "internal server error" });
              }
              return res
                .status(201)
                .json({ message: "Mandal Admin Created Successfully" });
            }
          );
        });
      });
    } else {
      const arr = [];
      const vil = result[0].village;
      const man = result[0].mandal;
      const dis = result[0].district;
      const role = "vadmin";
      const { username, password } = createUserNameAndPasswordForAdmins(
        role,
        mobileNumber
      );
      const hash = await bcrypt.hash(password, saltRound);
      const fetchVillageIdQuery = `SELECT village_id FROM villages WHERE village_name = ?`;
      connection.execute(fetchVillageIdQuery, [vil], (err, result) => {
        arr.push(result[0].village_id);
        const fetchMandalIdQuery = `SELECT mandal_id FROM mandals WHERE mandal_name = ?`;
        connection.execute(fetchMandalIdQuery, [man], (err, result) => {
          arr.push(result[0].mandal_id);
          const fetchDistrictIdQuery = `SELECT district_id FROM districts WHERE district_name = ?`;
          connection.execute(fetchDistrictIdQuery, [dis], (err, result) => {
            arr.push(result[0].district_id);
            const uid = `V${arr[0]}M${arr[1]}D${arr[2]}`;
            const villageAdminInsertQuery = `INSERT INTO users (name,mobile_number,username,password,village,mandal,district,profile_pic,uid,role) VALUES(?,?,?,?,?,?,?,?,?,?)`;
            connection.execute(
              villageAdminInsertQuery,
              [
                name,
                mobileNumber,
                username,
                hash,
                village,
                mandal,
                district,
                profilePic,
                uid,
                role,
              ],
              (err, result) => {
                if (err) {
                  return res
                    .status(500)
                    .json({ message: "internal server error" });
                }
                return res
                  .status(201)
                  .json({ message: "Village Admin Created Successfully" });
              }
            );
          });
        });
      });
    }
  });
});

app.get("/district-admins-list", (req, res) => {
  const fetchDistrictAdminsQuery = `SELECT * FROM users WHERE role = 'dadmin'`;
  connection.execute(fetchDistrictAdminsQuery, (err, result) => {
    if (err) {
      return res.status(500).json({ message: "internal server error" });
    }
    res.json(result);
  });
});

app.get("/districts-list", (req, res) => {
  const fetchDistricts = `SELECT * FROM districts`;
  connection.execute(fetchDistricts, (err, result) => {
    if (err) {
      return res.status(500).json({ message: "internal server error" });
    }
    res.json(result);
  });
});

app.get("/mandals-list", (req, res) => {
  const fetchMandals = `SELECT * FROM mandals`;
  connection.execute(fetchMandals, (err, result) => {
    if (err) {
      return res.status(500).json({ message: "internal server error" });
    }
    res.json(result);
  });
});

app.get("/villages-list", (req, res) => {
  const fetchVillages = `SELECT * FROM villages`;
  connection.execute(fetchVillages, (err, result) => {
    if (err) {
      return res.status(500).json({ message: "internal server error" });
    }
    res.json(result);
  });
});

app.post("/accept-mandal-admin-access-request/:id", (req, res) => {
  const requestId = req.params.id;
  const acceptMandalAdminRequest = `UPDATE accessadminrequests SET tag = 'S' WHERE request_id = ?`;
  connection.execute(acceptMandalAdminRequest, [requestId], (err, result) => {
    if (err) {
      return res.status(500).json({ message: "internal server error" });
    }
    return res.json({ message: "request successfully accepted" });
  });
});

app.get("/mandal-admins-list/:district", (req, res) => {
  const district = req.params.district;
  const fetchMandalAdminsQuery = `SELECT * FROM users WHERE role = 'madmin' AND district = ?`;
  connection.execute(fetchMandalAdminsQuery, [district], (err, result) => {
    if (err) {
      return res.status(500).json({ message: "Internal server error" });
    }
    res.json(result);
  });
});

app.get("/admin-details/:role", (req, res) => {
  const role = req.params.role;
  const fetchAdminDetails = `SELECT * FROM users WHERE role = ?`;
  connection.execute(fetchAdminDetails, [role], (err, result) => {
    if (err) {
      return res.status(500).json({ message: "internal server error" });
    }
    res.json(result);
  });
});

server.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
