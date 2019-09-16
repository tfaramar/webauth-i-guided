const express = require('express');
const helmet = require('helmet');
const cors = require('cors');

//import bcrypt.js hashing library
const bcrypt = require('bcryptjs');

const db = require('./database/dbConfig.js');
const Users = require('./users/users-model.js');

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());

server.get('/', (req, res) => {
  res.send("It's alive!");
});

server.post('/api/register', (req, res) => {
  let user = req.body;

  //hash password 2^12 times, and don't proceed in rest of program until password is hashed
  const hash = bcrypt.hashSync(user.password, 12);

  //overwrite use password with hash
  user.password = hash;

  Users.add(user)
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.post('/api/login', (req, res) => {
  let { username, password } = req.body;
  //first password after compareSync should be the unhashed/plaintext password, second should be the hashed password. bcrypt will make sure that these match one another.
  Users.findBy({ username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {
        res.status(200).json({ message: `Welcome ${user.username}!` });
      } else {
        res.status(401).json({ message: 'Invalid Credentials' });
      }
    })
    //if user doesn't exist, send back invalid credentials
    .catch(error => {
      res.status(500).json(error);
    });
});

//this endpoint should be protected
//req.headers should have correct username/password
//req.headers.username, req.headers.password
//if either of these is incorrect, user should be blocked from accessing this
server.get('/api/users', restricted, (req, res) => {
  Users.find()
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});

//custom middleware
function restricted (req, res, next) {
  const { username, password } = req.headers;

  if (username && password) {
    Users.findBy({ username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {
        next();
      } else {
        res.status(401).json({ message: "invalid credentials." })
      }
    })
  } else {
    res.status(400).json({ message: "Please provide a username and password." })
  }
}

const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));
