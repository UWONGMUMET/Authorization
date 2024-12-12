const express = require('express');
const Datastore = require('nedb-promises');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const config = require('./config');

const app = express();
app.use(express.json());

const users = Datastore.create('Users.db');

app.get('/', (req, res) => {
    res.send('REST API Authentication');
});

app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;

        if (!name || !email || !password) {
            return res.status(422).send({ msg: "Please fill in all fields." });
        }

        if (await users.findOne({ email })) {
            return res.status(409).send({ msg: "User already exists." });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = await users.insert({
            name,
            email,
            password: hashedPassword
        });

        return res.status(201).send({
            msg: 'User successfully registered',
            id: newUser._id,
        });
    } catch (err) {
        console.error(err);
        return res.status(500).send({ msg: err.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(422).send({ msg: "Please fill in all fields." });
        }

        const user = await users.findOne({ email });

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).send({ msg: "Invalid credentials." });
        }

        const accessToken = jwt.sign(
            { userId: user._id },
            config.accessTokenSecret,
            { subject: 'accessApi', expiresIn: config.accessTokenExpiresIn }
        );

        return res.status(200).send({
            id: user._id,
            name: user.name,
            email: user.email,
            accessToken: accessToken,
        });
    } catch (err) {
        console.error(err);
        return res.status(500).send({ msg: err.message });
    }
});

app.get('/api/users/current',ensureAuthenticated, async (req, res) => {
    try {
        const user = await users.findOne({_id: req.user.id})
        return res.status(200).send({
            id: user._id,
            name: user.name,
            email: user.email,
        })
    } catch (err) {
        return res.status(500).send({msg: err.msg});
    }
})

async function ensureAuthenticated(req, res, next) {
    const accessToken = req.headers.authorization

    if (!accessToken) {
        return res.status(401).send({msg: 'Access token not found'})
    }

    try {
        const decodedAccessToken = jwt.verify(accessToken, config.accessTokenSecret)

        req.user = {
            id: decodedAccessToken.userId,
        }

        next();
    } catch (err) {
        return res.status(401).send({msg: 'Access token invalid or expired'})
    }
}

app.listen(3000, () => console.log('Server started on port 3000'));
