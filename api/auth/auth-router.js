const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const bcrypt = require('bcryptjs')
const Users = require('../users/users-model')
const { JWT_SECRET } = require("../secrets"); // use this secret!
const jwt = require('jsonwebtoken')

router.post("/register", validateRoleName, async (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
    const { username, password }= req.body
    const { role_name } = req
    // bcrypting the password before saving
    const hash = bcrypt.hashSync(password, 8)
    // never save the plain text password in the db
  
    Users.add({username, password: hash, role_name})
    .then(saved => {
      console.log(saved)
      res.status(201).json(saved)
      })
      .catch(next) // our custom err handling middleware in server.js will trap this

});


router.post("/login", checkUsernameExists, async (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
    let { username, password  } = req.body
    Users.findBy({ username })
      .then(([user]) => {
        if (user && bcrypt.compareSync(password, user.password)) {
          const token = buildToken(user)
          res.status(200).json({ message: `${user.username} is back!`,token })
        } else {
          next({ status: 401, message: 'Invalid Credentials' })
        }
      })
      .catch(next)
});

function buildToken(user){
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name
  }
  const options = {
    // means the token will expire in 1 day
    expiresIn: '1d',
  }
  // next, we need to sign the token and return it
  return jwt.sign(payload,JWT_SECRET ,options)
}

module.exports = router;
