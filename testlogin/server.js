const cors = require('cors')
const express = require('express')
const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser')
const session = require('express-session')
const bcrypt = require('bcrypt')
const { MongoClient, ObjectId } = require('mongodb')
const bodyParser= require('body-parser')

const app = express()
const PORT = 5000
const url = "mongodb+srv://Four123:123Four@cluster0.yfnl7u8.mongodb.net/"
const client = new MongoClient(url)
const secret = "GN0000"

app.use(express.json())
app.use(cookieParser())
app.use(cors({
    credentials: true,
    origin: [`http://localhost:3000`]
}))


const connectDB = async () => {
    try {
        await client.connect();
        console.log("Connected to DB");
    } catch (err) {
        console.log("Error", err);
    }
}



app.get('/', (req,res)=>{
    res.send({ message: 'VLRPROJECTS' })
})

// hash and compare password


// Sign Up
app.post('/api/signup', async (req,res) => {
    try {
        const { password } = req.body;
        res.status(200).send({ password});
    } catch (error) {
        console.log(error);
    }
})

// Login
app.post('/api/login', async (req,res) => {
    try {
        await connectDB();
        const { email, password } = req.body;
        const findEmail = await client.db('VLRPROJECTS').collection('user').findOne({ email: email });
        if (!findEmail) {
            res.status(400).json({ message: 'email not found' });
            return false;
        }
        const MatchPassword = await matchPassword(password, findEmail.password);
        if (!MatchPassword) {
            res.status(400).json({ message: 'password not match' });
            return false;
        }
        const payload = { id: findEmail._id, role: findEmail.role };
        const token = jwt.sign(payload, secret, { expiresIn: '1h' });
        res.cookie('token', token, { httpOnly: true });
        res.status(200).json({ message: 'login success', result: findEmail});
    } catch (error) {
        console.log(error);
        res.status(500).json({ message: 'something went wrong' });
    }
})

// change password
app.put('/api/changepassword', async (req, res) => {
    try {
        const { id, password, newpassword } = req.body;
        await connectDB();
        const findUser = await client.db("VLRPROJECTS").collection("user").findOne({ _id: new ObjectId(id) });
        if (!findUser) {
            return res.status(400).send("User not found");
        }
        const match = await matchPassword(password, findUser.password);
        if (!match) {
            return res.status(400).send("Wrong password");
        }
        const hash = await hashPassword(newpassword);
        await client.db("VLRPROJECTS").collection("user").updateOne({ _id: new ObjectId(id) }, { $set: { password: hash } });
        res.status(200).send("Change Password Success");
    } catch (error) {
        console.log("Error", error);
    }
})

// Middleware, Check if user logged in
app.get('/api/checkToken', async (req, res) => {
    try {
        const token = req.cookies.token;
        if (!token) {
            return res.status(400).json({ message: "not token" });
        }
        const decode = jwt.verify(token, secret);
        res.status(200).send({ message: "have token", token: decode });
    } catch (error) {
        res.status(500).send({ message: "Something went wrong" });
    }
})

// Logout
app.post('/api/logout', (req, res) => {
    try {
        res.clearCookie('token');
        res.status(200).json({message : 'logout'});
    } catch (error) {
        console.log(error);        
    }
})

// Account
app.get('/api/getAccount/:id', async (req, res) => {
    try {
        const { id } = req.params;
        await connectDB();
        const findUser = await client.db("VLRPROJECTS").collection("user").findOne({ _id: new ObjectId(id) });
        if (!findUser) {
            res.status(404).json({ message: "User not found" });
            return false;
        }
        res.status(200).json(findUser);
    } catch (e) {
        res.status(500).json({ message: "Internal server error" });
    }    
})

app.listen(PORT, async () => {
    console.log(`Server started at port at http://localhost:${PORT}`)
})
