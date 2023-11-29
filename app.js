const express = require("express");
const path = require("path");
const { isBuffer } = require("util");
const bcrypt = require("bcrypt");
const session = require("express-session");
const MemoryStore = require("memorystore")(session);
const multer = require("multer");

// database connection
const con = require("./config/db");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
const upload = multer({ dest: "public/upload/" }).single("filetoupload");
//set "public" folder and its subfolders to be static folders, user can access it directly
app.use(express.static(path.join(__dirname, "public")));

// for session 
app.use(
  session({
    cookie: { maxAge: 24 * 60 * 60 * 1000 }, //1 day in millisec
    secret: "mysecretcode",
    resave: false,
    saveUninitialized: true,
    store: new MemoryStore({
      checkPeriod: 24 * 60 * 60 * 1000, // prune expired entries every 24h
    }),
  })
);


// ======================== SESSION ============================================================
app.use(
  session({
    cookie: { maxAge: 24 * 60 * 60 * 1000 }, //1 day in millisec
    secret: "mysecretcode",
    resave: false,
    saveUninitialized: true,
  })
);

// ============= Upload ==============
app.post("/uploading", function (req, res) {
  upload(req, res, function (err) {
    // req.file is the file from <input type="file" name="filetoupload">
    // req.body will hold the text fields, if there were any
    if (err) {
      console.log(err);
      res.status(500).send("Upload failed");
    } else {
      res.send("Upload is succesful");
    }
  });
});

// ============================== Create hashed password =======================================
app.get("/password/:pass", function (req, res) {
  const password = req.params.pass;
  const saltRounds = 10;
  bcrypt.hash(password, saltRounds, function (err, hash) {
    if (err) {
      return res.status(500).send("Hashing error");
    }
    //return hashed password, 60 characters
    // console.log(hash.length);
    res.send(hash);
  });
});
// ================================ REGISTERATION ==============================================
app.post("/register", function (req, res) {
  const {
    userid,
    name,
    password,
    address,
    email,
    number,
    role,
  } = req.body;
  const saltRounds = 10;
  bcrypt.hash(password, saltRounds, function (err, hash) {
    if (err) {
      return res.status(500).send("Hashing error");
    }
    const sql =
      "INSERT INTO user(userid, name, password, address, email, number,role) VALUE(?,?,?,?,?,?,?)";
    con.query(
      sql,
      [
        userid,
        name,
        hash,
        address,
        email,
        number,
        role,
      ],
      function (err, results) {
        if (err) {
          console.error(err);
          return res.status(500).send("Database server error");
        }
        if (results.affectedRows != 1) {
          console.error("Row added is not 1");
          return res.status(500).send("Add failed");
        }
        res.send("Add succesfully");
      }
    );
  });
});

// ================================= jgg ======================================================
app.post("/login", function (req, res) {
  const name = req.body.name;
  const password = req.body.password;
  const sql = "SELECT userid, password, role FROM user WHERE name = ?";
  con.query(sql, [name], function (err, results) {
    if (err) {
      return res.status(500).send("Database server error");
    }
    if (results.length != 1) {
      return res.status(400).send("Wrong username");
    }
    bcrypt.compare(password, results[0].password, function (err, same) {
      if (err) {
        res.status(503).send("Authentication server error");
      } else if (same == true) {
        req.session.userid = results[0].userid;
        req.session.name = name;
        req.session.password = password;
        //console.log(req.session.userid);
        //correct login send destination URL to client
        if (results[0].role == 1) {
          res.send("/homepage");
        } else {
          res.send("/admin");
        }
      } else {
        //wrong password
        res.status(400).send("Wrong password");
      }
    });
  });
});

app.post("/reset_password", function (req, res) {
  const name = req.body.name;
  const sql = "SELECT userid, name,password FROM user WHERE name = ?";
  con.query(sql, [name], function (err, results) {
    if (err) {
      console.log(err);
      return res.status(500).send("Database server error");
    }
    if (results.length != 1) {
      return res.status(400).send("Wrong username");
    } else {
      req.session.userid = results[0].userid;
      res.send("good");
    }
  });
});

app.get("/reset_password", function (req, res) {
  const userid = req.session.userid;
  const sql = "SELECT * FROM user WHERE userid = ?";
  con.query(sql, [userid], function (err, results) {
    if (err) {
      console.error(err);
      return res.status(500).send("Database server error");
    }
    res.json(results);
  });
});

app.put("/reset_password/:id", function (req, res) {
  const userid = req.session.userid;
  const password = req.body.password;
  const saltRounds = 10;
  const sql = "UPDATE user SET password = ? WHERE userid = ?";
  bcrypt.hash(password, saltRounds, function (err, hash) {
    if (err) {
      console.log(err);
      return res.status(500).send("Hashing error");
    }
    con.query(sql, [hash, userid], function (err, results) {
      if (err) {
        console.error(err);
        return res.status(500).send("Database server error");
      }
      if (results.affectedRows != 1) {
        console.log(results.affectedRows);
        console.error("Row updated is not 1");
        return res.status(500).send("Update failed");
      }
      res.send("update successful");
    });
  });
});

// =============================== GET infor from user table ====================================
app.get("/user", function (_req, res) {
  const sql = "SELECT * FROM user";
  con.query(sql, function (err, results) {
    if (err) {
      console.error(err);
      return res.status(500).send("Database server error");
    }
    res.json(results);
  });
});

// ------------- Delete a user --------------
app.delete("/user/:id", function (req, res) {
  const userid = req.params.id;
  const sql = "DELETE FROM user WHERE userid = ?";
  con.query(sql, [userid], function (err, results) {
    if (err) {
      console.error(err);
      return res.status(500).send("Database server error");
    }
    if (results.affectedRows != 1) {
      console.log(results.affectedRows);
      console.error("Row deleted is not 1");
      return res.status(500).send("Delete failed");
    }
    res.send("Delete succesfully");
  });
});

// ------------- Update a user --------------
app.put("/user/:id", function (req, res) {
  const userid = req.params.id;
  const updateProduct = req.body;
  const sql = "UPDATE user SET ? WHERE userid = ?";
  con.query(sql, [updateProduct, userid], function (err, results) {
    if (err) {
      console.error(err);
      return res.status(500).send("Database server error");
    }
    if (results.affectedRows != 1) {
      console.log(results.affectedRows);
      console.error("Row updated is not 1");
      return res.status(500).send("Update failed");
    }
    res.send("Update succesfully");
  });
});

// ------------- Add a new user --------------
app.post("/user", function (req, res) {
  const newProduct = req.body;
  const sql = "INSERT INTO user SET ?";
  con.query(sql, newProduct, function (err, results) {
    if (err) {
      console.error(err);
      return res.status(500).send("Database server error");
    }
    if (results.affectedRows != 1) {
      console.error("Row added is not 1");
      return res.status(500).send("Add failed");
    }
    res.send("Add succesfully");
  });
});

// ------------- Logout --------------
app.get("/logout", function (req, res) {
  //clear session variable
  req.session.destroy(function (err) {
    if (err) {
      console.error(err.message);
      res.status(500).send("Cannot clear session");
    } else {
      res.send("/login");
    }
  });
});

// =============================== GET infor from product table ====================================
app.get("/product", function (_req, res) {
  const sql = "SELECT * FROM product";
  con.query(sql, function (err, results) {
    if (err) {
      console.error(err);
      return res.status(500).send("Database server error");
    }
    res.json(results);
  });
});

// ------------- Delete a product  --------------
app.delete("/product/:id", function (req, res) {
  const productid = req.params.id;
  const sql = "DELETE FROM product WHERE productid = ?";
  con.query(sql, [productid], function (err, results) {
    if (err) {
      console.error(err);
      return res.status(500).send("Database server error");
    }
    if (results.affectedRows != 1) {
      console.log(results.affectedRows);
      console.error("Row deleted is not 1");
      return res.status(500).send("Delete failed");
    }
    res.send("Delete succesfully");
  });
});

// ------------- Update a order --------------
app.put("/product/:id", function (req, res) {
  const productid = req.params.id;
  const updateProduct = req.body;
  const sql = "UPDATE product SET ? WHERE productid = ?";
  con.query(sql, [updateProduct, productid], function (err, results) {
    if (err) {
      console.error(err);
      return res.status(500).send("Database server error");
    }
    if (results.affectedRows != 1) {
      console.log(results.affectedRows);
      console.error("Row updated is not 1");
      return res.status(500).send("Update failed");
    }
    res.send("Update succesfully");
  });
});

// ========================== new product =====================================
app.post("/product", function (req, res) {
  const newProduct = req.body;
  const sql = "INSERT INTO product SET ?";
  con.query(sql, newProduct, function (err, results) {
    if (err) {
      console.error(err);
      return res.status(500).send("Database server error");
    }
    if (results.affectedRows != 1) {
      console.error("Row added is not 1");
      return res.status(500).send("Add failed");
    }
    res.send("Add succesfully");
  });
});

app.get("/list", function (req, res) {
  const userid = req.session.userid;
  const sql = "SELECT * FROM buy_list WHERE userid = ?";
  con.query(sql, [userid], function (err, results) {
    if (err) {
      console.error(err);
      return res.status(500).send("Database server error");
    }
    res.json(results);
  });
});

// =============================== GET infor from buy_list table ====================================
app.get("/order", function (_req, res) {
  const sql = "SELECT * FROM buy_list";
  con.query(sql, function (err, results) {
    if (err) {
      console.error(err);
      return res.status(500).send("Database server error");
    }
    res.json(results);
  });
});

// ------------- Delete a order --------------
app.delete("/order/:id", function (req, res) {
  const orderid = req.params.id;
  const sql = "DELETE FROM buy_list WHERE orderid = ?";
  con.query(sql, [orderid], function (err, results) {
    if (err) {
      console.error(err);
      return res.status(500).send("Database server error");
    }
    if (results.affectedRows != 1) {
      console.log(results.affectedRows);
      console.error("Row deleted is not 1");
      return res.status(500).send("Delete failed");
    }
    res.send("Delete succesfully");
  });
});

// ------------- Update a order --------------
app.put("/order/:id", function (req, res) {
  const orderid = req.params.id;
  const updateProduct = req.body;
  const sql = "UPDATE buy_list SET ? WHERE orderid = ?";
  con.query(sql, [updateProduct, orderid], function (err, results) {
    if (err) {
      console.error(err);
      return res.status(500).send("Database server error");
    }
    if (results.affectedRows != 1) {
      console.log(results.affectedRows);
      console.error("Row updated is not 1");
      return res.status(500).send("Update failed");
    }
    res.send("Update succesfully");
  });
});

//============================== get information from food table ===================================================
app.get("/food", function (_req, res) {
  const sql = "SELECT * FROM food";
  con.query(sql, function (err, results) {
    if (err) {
      console.error(err);
      return res.status(500).send("Database server error");
    }
    res.json(results);
  });
});

// ------------- Delete a food --------------
app.delete("/food/:id", function (req, res) {
  const fid = req.params.id;
  const sql = "DELETE FROM food WHERE fid = ?";
  con.query(sql, [fid], function (err, results) {
    if (err) {
      console.error(err);
      return res.status(500).send("Database server error");
    }
    if (results.affectedRows != 1) {
      console.log(results.affectedRows);
      console.error("Row deleted is not 1");
      return res.status(500).send("Delete failed");
    }
    res.send("Delete succesfully");
  });
});

// ------------- Update a food --------------
app.put("/food/:id", function (req, res) {
  const fid = req.params.id;
  const updateProduct = req.body;
  const sql = "UPDATE food SET ? WHERE fid = ?";
  con.query(sql, [updateProduct, fid], function (err, results) {
    if (err) {
      console.error(err);
      return res.status(500).send("Database server error");
    }
    if (results.affectedRows != 1) {
      console.log(results.affectedRows);
      console.error("Row updated is not 1");
      return res.status(500).send("Update failed");
    }
    res.send("Update succesfully");
  });
});

// ------------- Add a new food --------------
app.post("/food", function (req, res) {
  const newProduct = req.body;
  const sql = "INSERT INTO food SET ?";
  con.query(sql, newProduct, function (err, results) {
    if (err) {
      console.error(err);
      return res.status(500).send("Database server error");
    }
    if (results.affectedRows != 1) {
      console.error("Row added is not 1");
      return res.status(500).send("Add failed");
    }
    res.send("Add succesfully");
  });
});

//=========================== get infofrom from equipment table ==================================================
app.get("/equipment", function (_req, res) {
  const sql = "SELECT * FROM equipment";
  con.query(sql, function (err, results) {
    if (err) {
      console.error(err);
      return res.status(500).send("Database server error");
    }
    res.json(results);
  });
});

// ------------- Delete a equipment --------------
app.delete("/equipment/:id", function (req, res) {
  const equid = req.params.id;
  const sql = "DELETE FROM equipment WHERE equid = ?";
  con.query(sql, [equid], function (err, results) {
    if (err) {
      console.error(err);
      return res.status(500).send("Database server error");
    }
    if (results.affectedRows != 1) {
      console.log(results.affectedRows);
      console.error("Row deleted is not 1");
      return res.status(500).send("Delete failed");
    }
    res.send("Delete succesfully");
  });
});

// ------------- Update a equipment --------------
app.put("/equipment/:id", function (req, res) {
  const equid = req.params.id;
  const updateProduct = req.body;
  const sql = "UPDATE equipment SET ? WHERE equid = ?";
  con.query(sql, [updateProduct, equid], function (err, results) {
    if (err) {
      console.error(err);
      return res.status(500).send("Database server error");
    }
    if (results.affectedRows != 1) {
      console.log(results.affectedRows);
      console.error("Row updated is not 1");
      return res.status(500).send("Update failed");
    }
    res.send("Update succesfully");
  });
});

// ------------- Add a new equipment --------------
app.post("/equipment", function (req, res) {
  const newProduct = req.body;
  const sql = "INSERT INTO equipment SET ?";
  con.query(sql, newProduct, function (err, results) {
    if (err) {
      console.error(err);
      return res.status(500).send("Database server error");
    }
    if (results.affectedRows != 1) {
      console.error("Row added is not 1");
      return res.status(500).send("Add failed");
    }
    res.send("Add succesfully");
  });
});

// ------------- Add a new product --------------
app.post("/product_order", function (req, res) {
  const userid = req.session.userid;
  const orderStatus = 'ordered';
  const { order_p_id, productid, image, amount, price, date, time, status ,expiration_date} =
    req.body;
  const sql =
    "INSERT INTO product_order(order_p_id,productid,userid,image,amount,price,date,time,status,orderStatus,expiration_date) VALUES(?,?,?,?,?,?,?,?,?,?,?) ";
  con.query(
    sql,
    [order_p_id, productid, userid, image, amount, price, date, time, status, orderStatus,expiration_date],
    function (err, results) {
      if (err) {
        console.error(err);
        return res.status(500).send("Database server error");
      }
      if (results.affectedRows != 1) {
        console.error("Row added is not 1");
        return res.status(500).send("Add failed");
      }
      res.send("Add succesfully");
    }
  );
});
//=========================== get infofrom from product table ==================================================
app.get("/product_order", function (req, res) {
  const userid = req.session.userid;
  const sql = "SELECT * FROM product_order WHERE userid = ? AND status = 'waiting for payment'";
  con.query(sql, [userid], function (err, results) {
    if (err) {
      console.error(err);
      return res.status(500).send("Database server error");
    }
    res.json(results);
  });
});

// ------------- Update a product --------------
app.put("/product_order/:id", function (req, res) {
  const order_p_id = req.params.id;
  const updateProduct = req.body;
  const sql = "UPDATE product_order SET ? WHERE order_p_id = ?";
  con.query(sql, [updateProduct, order_p_id], function (err, results) {
    if (err) {
      console.error(err);
      return res.status(500).send("Database server error");
    }
    if (results.affectedRows != 1) {
      console.log(results.affectedRows);
      console.error("Row updated is not 1");
      return res.status(500).send("Update failed");
    }
    res.send("Update succesfully");
  });
});
// ------------- Delete a product --------------
app.delete("/product_order/:id", function (req, res) {
  const order_p_id = req.params.id;
  const sql = "DELETE FROM product_order WHERE order_p_id = ?";
  con.query(sql, [order_p_id], function (err, results) {
    if (err) {
      console.error(err);
      return res.status(500).send("Database server error");
    }
    if (results.affectedRows != 1) {
      console.log(results.affectedRows);
      console.error("Row deleted is not 1");
      return res.status(500).send("Delete failed");
    }
    res.send("Delete succesfully");
  });
});

// ------------- Add a new equipment --------------
app.post("/equipment_order", function (req, res) {
  const userid = req.session.userid;
  const { order_e_id, equipmentid, amount, price, date, time, status, image } =
    req.body;
  const sql =
    "INSERT INTO equipment_order(order_e_id,equipmentid,userid,amount,price,date,time,status,image) VALUE(?,?,?,?,?,?,?,?,?) ";
  con.query(
    sql,
    [order_e_id, equipmentid, userid, amount, price, date, time, status, image],
    function (err, results) {
      if (err) {
        console.error(err);
        return res.status(500).send("Database server error");
      }
      if (results.affectedRows != 1) {
        console.error("Row added is not 1");
        return res.status(500).send("Add failed");
      }
      res.send("Add succesfully");
    }
  );
});
//=========================== get infofrom from equipment table ==================================================
app.get("/equipment_order", function (req, res) {
  const userid = req.session.userid;
  const sql = "SELECT * FROM equipment_order WHERE userid = ? AND status = 'waiting for payment'";
  con.query(sql, [userid], function (err, results) {
    if (err) {
      console.error(err);
      return res.status(500).send("Database server error");
    }
    res.json(results);
  });
});
// ------------- Update a equipment --------------
app.put("/equipment_order/:id", function (req, res) {
  const order_e_id = req.params.id;
  const updateProduct = req.body;
  const sql = "UPDATE equipment_order SET ? WHERE order_e_id = ?";
  con.query(sql, [updateProduct, order_e_id], function (err, results) {
    if (err) {
      console.error(err);
      return res.status(500).send("Database server error");
    }
    if (results.affectedRows != 1) {
      console.log(results.affectedRows);
      console.error("Row updated is not 1");
      return res.status(500).send("Update failed");
    }
    res.send("Update succesfully");
  });
});
// ------------- Delete a equipment --------------
app.delete("/equipment_order/:id", function (req, res) {
  const order_e_id = req.params.id;
  const sql = "DELETE FROM equipment_order WHERE order_e_id = ?";
  con.query(sql, [order_e_id], function (err, results) {
    if (err) {
      console.error(err);
      return res.status(500).send("Database server error");
    }
    if (results.affectedRows != 1) {
      console.log(results.affectedRows);
      console.error("Row deleted is not 1");
      return res.status(500).send("Delete failed");
    }
    res.send("Delete succesfully");
  });
});

// ------------- Add a new food --------------
app.post("/food_order", function (req, res) {
  const userid = req.session.userid;
  const { order_f_id, foodid, image, amount, price, date, time, status } =
    req.body;
  const sql =
    "INSERT INTO food_order(order_f_id,foodid,image,userid,amount,price,date,time,status) VALUE(?,?,?,?,?,?,?,?,?) ";
  con.query(
    sql,
    [order_f_id, foodid, image, userid, amount, price, date, time, status],
    function (err, results) {
      if (err) {
        console.error(err);
        return res.status(500).send("Database server error");
      }
      if (results.affectedRows != 1) {
        console.error("Row added is not 1");
        return res.status(500).send("Add failed");
      }
      res.send("Add succesfully");
    }
  );
});
//=========================== get infofrom from food table ==================================================
app.get("/food_order", function (req, res) {
  const userid = req.session.userid;
  const sql = "SELECT * FROM food_order WHERE userid = ? AND status = 'waiting for payment' ";
  con.query(sql, [userid], function (err, results) {
    if (err) {
      console.error(err);
      return res.status(500).send("Database server error");
    }
    res.json(results);
  });
});
// ------------- Update a food --------------
app.put("/food_order/:id", function (req, res) {
  const order_f_id = req.params.id;
  const updateProduct = req.body;
  const sql = "UPDATE food_order SET ? WHERE order_f_id = ?";
  con.query(sql, [updateProduct, order_f_id], function (err, results) {
    if (err) {
      console.error(err);
      return res.status(500).send("Database server error");
    }
    if (results.affectedRows != 1) {
      console.log(results.affectedRows);
      console.error("Row updated is not 1");
      return res.status(500).send("Update failed");
    }
    res.send("Update succesfully");
  });
});
// ------------- Delete a food --------------
app.delete("/food_order/:id", function (req, res) {
  const order_f_id = req.params.id;
  const sql = "DELETE FROM food_order WHERE order_f_id = ?";
  con.query(sql, [order_f_id], function (err, results) {
    if (err) {
      console.error(err);
      return res.status(500).send("Database server error");
    }
    if (results.affectedRows != 1) {
      console.log(results.affectedRows);
      console.error("Row deleted is not 1");
      return res.status(500).send("Delete failed");
    }
    res.send("Delete succesfully");
  });
});

//=========================== get order from product table ==================================================
app.get("/get_product", function (_req, res) {
  const sql = "SELECT * FROM product_order";
  con.query(sql, function (err, results) {
    if (err) {
      console.error(err);
      return res.status(500).send("Database server error");
    }
    res.json(results);
  });
});

app.put('/get_product/:id', (req, res) => {
  const order_p_id = req.params.id;
  const orderStatus = req.body.orderStatus;
  const sql = 'UPDATE product_order SET orderStatus = ? WHERE order_p_id = ?';
  con.query(sql, [orderStatus, order_p_id], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).send("Database server error");
    }
    if (results.affectedRows !== 1) {
      console.error("Row not updated");
      return res.status(500).send("Update failed");
    }
    res.send("Update successful");
  });
});
app.put('/get_food/:id', (req, res) => {
  const order_f_id = req.params.id;
  const orderStatus = req.body.orderStatus;
  const sql = 'UPDATE food_order SET orderStatus = ? WHERE order_f_id = ?';
  con.query(sql, [orderStatus, order_f_id], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).send("Database server error");
    }
    if (results.affectedRows !== 1) {
      console.error("Row not updated");
      return res.status(500).send("Update failed");
    }
    res.send("Update successful");
  });
});
app.put('/get_equipment/:id', (req, res) => {
  const order_e_id = req.params.id;
  const orderStatus = req.body.orderStatus;
  const sql = 'UPDATE equipment_order SET orderStatus = ? WHERE order_e_id = ?';
  con.query(sql, [orderStatus, order_e_id], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).send("Database server error");
    }
    if (results.affectedRows !== 1) {
      console.error("Row not updated");
      return res.status(500).send("Update failed");
    }
    res.send("Update successful");
  });
});
// ------------- Delete a food --------------
app.delete("/get_product/:id", function (req, res) {
  const order_p_id = req.params.id;
  const sql = "DELETE FROM product_order WHERE order_p_id = ?";
  con.query(sql, [order_p_id,], function (err, results) {
    if (err) {
      console.error(err);
      return res.status(500).send("Database server error");
    }
    if (results.affectedRows != 1) {
      console.log(results.affectedRows);
      console.error("Row deleted is not 1");
      return res.status(500).send("Delete failed");
    }
    res.send("Delete succesfully");
  });
});

//=========================== get infofrom from food table ==================================================
app.get("/get_food", function (_req, res) {
  const sql = "SELECT * FROM food_order";
  con.query(sql, function (err, results) {
    if (err) {
      console.error(err);
      return res.status(500).send("Database server error");
    }
    res.json(results);
  });
});
// ------------- Delete a food --------------
app.delete("/get_food/:id", function (req, res) {
  const order_f_id = req.params.id;
  const sql = "DELETE FROM food_order WHERE order_f_id = ?";
  con.query(sql, [order_f_id], function (err, results) {
    if (err) {
      console.error(err);
      return res.status(500).send("Database server error");
    }
    if (results.affectedRows != 1) {
      console.log(results.affectedRows);
      console.error("Row deleted is not 1");
      return res.status(500).send("Delete failed");
    }
    res.send("Delete succesfully");
  });
});

//=========================== get infofrom from food table ==================================================
app.get("/get_equipment", function (_req, res) {
  const sql = "SELECT * FROM equipment_order";
  con.query(sql, function (err, results) {
    if (err) {
      console.error(err);
      return res.status(500).send("Database server error");
    }
    res.json(results);
  });
});
// ------------- Delete a food --------------
app.delete("/get_equipment/:id", function (req, res) {
  const order_e_id = req.params.id;
  const sql = "DELETE FROM equipment_order WHERE order_e_id = ?";
  con.query(sql, [order_e_id], function (err, results) {
    if (err) {
      console.error(err);
      return res.status(500).send("Database server error");
    }
    if (results.affectedRows != 1) {
      console.log(results.affectedRows);
      console.error("Row deleted is not 1");
      return res.status(500).send("Delete failed");
    }
    res.send("Delete succesfully");
  });
});



//======================================== upload_image =================================
app.post("/upload_image", (req, res) => {
  const userid = req.body.userid;
  const image = req.body.image;
  const image_id = req.body.image_id;
  const sql = "INSERT INTO profile_image(image_id,userid,image) VALUE(?,?,?)";
  con.query(sql, [image_id, userid, image], (err, results) => {
    if (err) {
      console.error(err);
    }
    if (results.affectedRows != 1) {
      console.error("affected many rows");
    }
    res.send("succesfully");
  });
});


// ================================ get timmer =======================================
app.get('/get_timer', function (req, res) {
  const userid = req.session.userid;
  const sql = "SELECT * FROM  product_order WHERE userid = ?"
  con.query(sql, [userid], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).send("Database server error");
    }
    res.json(results);
  });
});


// =============================== PROFILE ===========================================
app.get('/getProfile', (req, res) => {
  const userid = req.session.userid;
  const sql = 'SELECT * FROM user WHERE userid = ?'
  con.query(sql, [userid], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).send("Database server error");
    }
    res.json(results);
  });
});

app.get('/getProdictHistory', (req, res) => {
  const userid = req.session.userid;
  const sql = 'SELECT * FROM product_order WHERE userid =?'
  con.query(sql, [userid], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).send("Database server error");
    }
    res.json(results);
  });
});

app.get('/getEquipHistory', (req, res) => {
  const userid = req.session.userid;
  const sql = 'SELECT * FROM equipment_order WHERE userid =?'
  con.query(sql, [userid], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).send("Database server error");
    }
    res.json(results);
  });
});

app.get('/getFoodHistory', (req, res) => {
  const userid = req.session.userid;
  const sql = 'SELECT * FROM food_order WHERE userid =?'
  con.query(sql, [userid], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).send("Database server error");
    }
    res.json(results);
  });
});

app.put('/editeProfile/:id', (req, res) => {
  const userid = req.session.userid;
  const updateProduct = req.body;
  const sql = 'UPDATE user SET ? WHERE userid = ?';
  con.query(sql, [updateProduct, userid], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Data base error');
    }
    if (results.affectedRows !== 1) {
      console.error('Row not update');
      return res.status(500).send('Update failed');
    }
    res.send('Update successful');
  })
})

// ============================== send data to finish entities =========================
// app.post('/finish_POrder', (req, res) => {
//   const { id, order_p_id, image, userid, amount, product_id, price, date, time, status, orderStatus } = req.body;
//   const sql = 'INSERT INTO finish_order_product (id, order_p_id, image, userid, amount, product_id, price, date, time, status, orderStatus) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)';
//   con.query(sql, [id, order_p_id, image, userid, amount, product_id, price, date, time, status, orderStatus], (err, results) => {
//     if (err) {
//       console.error(err);
//       return res.status(500).send("Error occurred");
//     }
//     if (results.affectedRows !== 1) {
//       console.error("Affected many rows");
//       return res.status(500).send("Error occurred");
//     }
//     res.send("Successfully inserted");
//   });
// });
// app.post('/finish_FOrder', (req, res) => {
//   const { id, order_f_id, image, userid, amount, foodid, price, date, time, status, orderStatus } = req.body;
//   const sql = 'INSERT INTO finish_order_food (id, order_f_id, image, userid, amount, foodid, price, date, time, status, orderStatus) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)';
//   con.query(sql, [id, order_f_id, image, userid, amount, foodid, price, date, time, status, orderStatus], (err, results) => {
//     if (err) {
//       console.error(err);
//       return res.status(500).send("Error occurred");
//     }
//     if (results.affectedRows !== 1) {
//       console.error("Affected many rows");
//       return res.status(500).send("Error occurred");
//     }
//     res.send("Successfully inserted");
//   });
// });
// app.post('/finish_EOrder', (req, res) => {
//   const { id, order_e_id, image, userid, amount, equipmentid, price, date, time, status, orderStatus } = req.body;
//   const sql = 'INSERT INTO finish_order_equipment (id, order_e_id, image, userid, amount, equipmentid, price, date, time, status, orderStatus) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)';
//   con.query(sql, [id, order_e_id, image, userid, amount, equipmentid, price, date, time, status, orderStatus], (err, results) => {
//     if (err) {
//       console.error(err);
//       return res.status(500).send("Error occurred");
//     }
//     if (results.affectedRows !== 1) {
//       console.error("Affected many rows");
//       return res.status(500).send("Error occurred");
//     }
//     res.send("Successfully inserted");
//   });
// });





// ============================= Page ==================================================


app.get("/test", function (req, res) {
  res.sendFile(path.join(__dirname, "views/test.html"));
});
app.get("/forget", function (req, res) {
  res.sendFile(path.join(__dirname, "views/forget.html"));
});
app.get("/profile", function (req, res) {
  if(req.session.name){
  res.sendFile(path.join(__dirname, "views/profile.html"));
  }else{
    res.redirect('/login');
  }
});

app.get("/cart", function (req, res) {
  if (req.session.name) {
    res.sendFile(path.join(__dirname, "views/basket.html"));
  } else {
    res.redirect('/login');
  }
});

app.get("/homepage2", function (req, res) {
  res.sendFile(path.join(__dirname, "views/homepage2.html"));
});

// =============== HOMEPAGE =====================
//localhost:3000/homepage
app.get("/homepage", function (req, res) {
  if (req.session.name) {
    res.sendFile(path.join(__dirname, "views/homepage.html"));
  } else {
    res.redirect('/login');
  }
});

// ================ ADMIN ========================
app.get("/admin/dashboard", function (req, res) {
  if (req.session.name) {
    res.sendFile(path.join(__dirname, "views/dashboard.html"));
  } else {
    res.redirect('/login');
  }
});
// ================ ADMIN ========================
app.get("/admin/order/equipment", function (req, res) {
  if (req.session.name) {
    res.sendFile(path.join(__dirname, "views/admin_equipment_order.html"));
  } else {
    res.redirect('/login');
  }
});
// ================ ADMIN ========================
app.get("/admin/order/food", function (req, res) {
  if (req.session.name) {
    res.sendFile(path.join(__dirname, "views/admin_food_order.html"));
  } else {
    res.redirect('/login');
  }
});
// ================ ADMIN ========================
app.get("/admin/order/product", function (req, res) {
  if (req.session.name) {
    res.sendFile(path.join(__dirname, "views/admin_product_order.html"));
  } else {
    res.redirect('/login');
  }
});
// ================ ADMIN ========================
app.get("/admin/table/equipment", function (req, res) {
  if (req.session.name) {
    res.sendFile(path.join(__dirname, "views/admin_equipment.html"));
  } else {
    res.redirect('/login');
  }
});
// ================ ADMIN ========================
app.get("/admin/table/food", function (req, res) {
  if (req.session.name) {
    res.sendFile(path.join(__dirname, "views/admin_food.html"));
  } else {
    res.redirect('/login');
  }
});
// ================ ADMIN ========================
app.get("/admin/table/product", function (req, res) {
  if (req.session.name) {
    res.sendFile(path.join(__dirname, "views/admin_product.html"));
  } else {
    res.redirect('/login');
  }
});

// ================ ADMIN ========================
//localhost:3000/admin
app.get("/admin", function (req, res) {
  if (req.session.name) {
    res.sendFile(path.join(__dirname, "views/admin.html"));
  } else {
    res.redirect('/login');
  }
});
//localhost:3000/login
// ====================login========================
app.get("/login", function (req, res) {
  res.sendFile(path.join(__dirname, "views/login.html"));
});
//localhost:3000/regis
app.get("/regis", function (req, res) {
  res.sendFile(path.join(__dirname, "views/register.html"));
});
//localhost:3000/
//=================Root===============================
app.get("/", function (req, res) {
  res.sendFile(path.join(__dirname, "views/root.html"));
});
const port = 3000;
app.listen(port, function () {
  console.log("Server is ready at " + port);
});
