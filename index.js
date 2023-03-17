const express = require('express');
const cors = require('cors');
const mysql2 = require('mysql2');
const app = express();
require('dotenv').config();
var bodyParser = require('body-parser');
var jsonParser = bodyParser.json();

const bcrypt = require('bcrypt');
const saltRounds = 10;

var jwt = require('jsonwebtoken');
const secret = "TheSuperAppIoT-RegSystems"


// Cors คือ Cross Origin Resource Sharing เป็นกลไลที่ทำให้ Web Server 
// ให้อนุญาตหรือไม่อนุญาต ร้องขอทรัพยากรใดๆ ในหน้า Web ที่ถูกเรียกจาก Domain อื่น
// ที่ไม่ใช่ Domain ที่หน้า Web นั้นอยู่
app.use(express.json());
app.use(cors());

const db = mysql2.createConnection(process.env.DATABASE_URL)

app.get("/", (req, res) => {
    res.json("This is server-side. AKA Backend")
})

////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////// Admin Section ////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////

//Fetch admin
app.get('/admin', (req, res) => {
    const q = "SELECT * FROM admin"
    db.query(q, (err, data) => {
        if (err) return res.status(500).json({
            "status": 500,
            "message": "Internal Server Error",
        })
        return res.json(data)
    });
});

//Fetch admin by ID
app.get('/admin/:id', (req, res) => {
    let id = req.params.id;
    db.query("SELECT * FROM admin WHERE id = ?", id, (error, results, fields) => {
        if (error) throw error;
        let message = "";
        if (results === undefined || results.length == 0) {
            message = "admin not found"
        } else {
            message = "successfuly retrieved admin data"
        }
        return res.send({ error: false, data: results[0], message: message })
    })
})

//Creat admin
app.post('/regadmin', (req, res) => {
    bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
        const q = "INSERT INTO admin (`username`,`password`,`fname`,`lname`,`email`) VALUES (?)"
        const values = [
            req.body.username,
            hash,
            req.body.fname,
            req.body.lname,
            req.body.email,
        ];
        db.query(q, [values], (err, data) => {
            if (err) return res.json(err)
            return res.json(data)
        })
    });
})

//Delete admin by ID
app.delete("/deleteadmin/:id", (req, res) => {
    const adminId = req.params.id;
    const q = "DELETE FROM admin WHERE id = ?";

    db.query(q, [adminId], (err, data) => {
        if (err) return res.json(err)
        return res.json("Admin has been deleted successfully")
    });
});

//Update admin
app.put("/updateadmin/:id", (req, res) => {
    const adminId = req.params.id;
    const q = "UPDATE admin SET `username` = ?, `password` = ?, `fname` = ?, `lname` = ?, `email` = ? WHERE id = ?";

    const values = [
        req.body.username,
        req.body.password,
        req.body.fname,
        req.body.lname,
        req.body.email,
    ];
    db.query(q, [...values, adminId], (err, data) => {
        if (err) return res.json(err)
        return res.json("Admin has been updated successfully")
    });
});

// Admin Routes Login
app.post('/login', jsonParser, function (req, res, next) {
    db.execute(
        'SELECT * FROM admin WHERE username = ?',
        [req.body.username,],
        function (err, admin, fields) {
            if (err) { res.json({ status: 'error', message: err }); return }
            if (admin.length == 0) { res.json({ status: 'error', message: 'no user found' }); return }
            bcrypt.compare(req.body.password, admin[0].password, function (err, isLogin) {
                if (isLogin) {
                    var token = jwt.sign({ email: admin[0].email }, secret);
                    res.json({ status: "ok", message: 'login success', token })
                } else {
                    res.json({ status: "error", message: 'login fail' })
                }
            });
        }
    );
});

// Authentication Admin
app.post('/auth', jsonParser, function (req, res, next) {
    try {
        const token = req.headers.authorization.split(' ')[1]
        var decoded = jwt.verify(token, secret);
        res.json({ status: 'ok', decoded })
    } catch (err) {
        res.json({ status: 'err', message: err.message })
    }
});


////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////// User Section ////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////

//Fetch users
app.get('/users', (req, res) => {
    const q = "SELECT * FROM users"
    db.query(q, (err, data) => {
        if (err) return res.json(err)
        return res.json(data)
    });
});

//Add users
app.post('/useradd', (req, res) => {
    const q = "INSERT INTO users (`title`,`fname`,`lname`,`age`,`phone`,`email`,`jobtitle`,`company`,`description`) VALUES (?)"
    const values = [
        req.body.title,
        req.body.fname,
        req.body.lname,
        req.body.age,
        req.body.phone,
        req.body.email,
        req.body.jobtitle,
        req.body.company,
        req.body.description,
    ];
    db.query(q, [values], (err, data) => {
        if (err) return res.json(err)
        return res.json(data)
    })
})

//Fetch user by ID
app.get('/users/:id', (req, res) => {
    let id = req.params.id;
    db.query("SELECT * FROM users WHERE id = ?", id, (error, results, fields) => {
        if (error) throw error;
        let message = "";
        if (results === undefined || results.length == 0) {
            message = "users not found"
        } else {
            message = "successfuly retrieved users data"
        }
        return res.send({ error: false, data: results[0], message: message })
    })
})

//Update user
app.put('/usersupdate/:id', (req, res) => {
    const userId = req.params.id;
    const q = "UPDATE users SET `title` = ?, `fname` = ?, `lname` = ?,`age` = ?,`phone` = ?, `email` = ?, `jobtitle` = ?,`company` = ?,`description` = ? WHERE id = ?";

    const values = [
        req.body.title,
        req.body.fname,
        req.body.lname,
        req.body.age,
        req.body.phone,
        req.body.email,
        req.body.jobtitle,
        req.body.company,
        req.body.description,
    ];
    db.query(q, [...values, userId], (err, data) => {
        if (err) return res.json(err)
        return res.json("Users has been updated successfully")
    });
})

//Delete user by ID
app.delete("/deleteuser/:id", (req, res) => {
    const userId = req.params.id;
    const q = "DELETE FROM users WHERE id = ?";

    db.query(q, [userId], (err, data) => {
        if (err) return res.json(err)
        return res.json("User has been deleted successfully")
    });
});

//QR Code
app.post('/qrcode', (req, res) => {
    let title = req.body.title;
    let fname = req.body.fname;
    let lname = req.body.lname;
    let age = req.body.age;
    let phone = req.body.phone;
    let email = req.body.email;
    let jobtitle = req.body.jobtitle;
    let company = req.body.company;
    let description = req.body.description;

    console.log(req);
    if (!title || !fname || !lname || !phone || !email || !company || !phone || !jobtitle || !company) {
        console.log(res);
        return res.status(400).send({ error: true, message: "enter register" });
    } else {
        db.query('INSERT INTO users (title, fname, lname, age, phone, email, jobtitle, company, description) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [title, fname, lname, age, phone, email, jobtitle, company, description],
            (error, results, fields) => {
                if (error) throw error;
                return res.send({ error: false, data: results, message: "Successfully added" })
            })
    }
});

app.delete('/qrcode/del', (req, res) => {
    let fname = req.body.fname;

    if (!fname) {
        return res.status(400).send({ error: true, message: "Please provide names" });
    } else {
        db.query('DELETE FROM users WHERE fname = ?',
            [fname],
            (error, results, fields) => {
                if (error) throw error;

                let message = "";
                if (results.affectedRows === 0) {
                    message = "user not found";
                } else {
                    message = "user successfully deleted";
                }

                return res.send({ error: false, data: results, message: message })
            })
    }
})


exports.countAllUsers = async (req, res) => {
    const uId = req.params.id;
    db.query(
        "SELECT COUNT(*) FROM users WHERE id = ?",
        [uId],
        (err, count) => {
            if (err) {
                res.status(500).json({ err });
                console.log(err);
            } else {
                console.log(count)
                res.status(200).json(count);
            }
        }
    );
};

////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////// Other Backend ///////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////


// app.get('/alluser', (req, res) => {
//     const q = "SELECT COUNT(*) FROM users;"
//     db.query(q, (err, data) => {
//         if (err) return res.json(err)
//         return res.json(data)
//     });
// });


////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////// Port Section ////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////


app.listen('3333', () => {
    console.log('Server is running on port 3333');
})

////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////


