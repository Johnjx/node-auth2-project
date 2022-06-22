const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const Users = require('../users/users-model');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

router.post("/register", validateRoleName, async (req, res, next) => {
  const { username, password, role_name } = req.body;

  const hash = bcrypt.hashSync(password, 10);
  const user = await Users.add({ username, password: hash, role_name});

  res.status(201).json(user);


  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:`
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */

});


router.post("/login", checkUsernameExists, (req, res, next) => {
  let { password, username } = req.body;
  password = password.toString();
  let userPassword = req.existingUser.password;

  if (bcrypt.compareSync(password, userPassword) == false) {
    next({ status: 401, message: 'Invalid Credentials' });
    return;
  }

  const token = generateToken(req.existingUser);
  res.json({ message: `${username} is back!`, token });

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
});

function generateToken(user) {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name,
  };
  const options = {
    expiresIn: '1d',
  };

  return jwt.sign(payload, JWT_SECRET, options);
}

module.exports = router;
