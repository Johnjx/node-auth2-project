const { JWT_SECRET } = require("../secrets"); // use this secret!
const Users = require('../users/users-model');
const jwt = require('jsonwebtoken');

const restricted = (req, res, next) => {
  const token = req.headers.authorization;
  if (token == null) {
    next({ status: 401, message: "Token required"});
    return;
  }
  
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err != null) {
      next({ status: 401, message: "Token invalid"});
      return;
    }

    req.decodedJwt = decoded;
    next();
  })

  /*
    If the user does not provide a token in the Authorization header:
    status 401
    {
      "message": "Token required"
    }

    If the provided token does not verify:
    status 401
    {
      "message": "Token invalid"
    }

    Put the decoded token in the req object, to make life easier for middlewares downstream!
  */
}

const only = role_name => (req, res, next) => {
  if (req.decodedJwt.role_name !== role_name) {
    next({ status: 403, message: "This is not for you"});
    return;
  }

  next();
  /*
    If the user does not provide a token in the Authorization header with a role_name
    inside its payload matching the role_name passed to this function as its argument:
    status 403
    {
      "message": "This is not for you"
    }

    Pull the decoded token from the req object, to avoid verifying it again!
  */
}


const checkUsernameExists = async (req, res, next) => {
  const { username } = req.body;

  const existingUser = await Users.findBy({username});
  if (!existingUser.length) {
    next({ status: 401, message: "Invalid credentials" });
    return;
  }

  req.existingUser = existingUser[0];
  next();
  /*
    If the username in req.body does NOT exist in the database
    status 401
    {
      "message": "Invalid credentials"
    }
  */
}


const validateRoleName = (req, res, next) => {
  let { role_name } = req.body;

  if (typeof role_name !== 'string' || role_name.trim().length === '') {
    req.body.role_name = 'student';
    next();
    return;
  }

  if (role_name.trim() === 'admin') {
    next({status: 422, message: "Role name can not be admin"});
    return;
  }

  if (role_name.trim().length > 32) {
    next({status: 422, message: "Role name can not be longer than 32 chars"});
    return;
  }

  req.body.role_name = role_name.trim();
  next();

  /*
    If the role_name in the body is valid, set req.role_name to be the trimmed string and proceed.

    { "username": "anna", "password": "1234", "role_name": "angel" }

    If role_name is missing from req.body, or if after trimming it is just an empty string,
    set req.role_name to be 'student' and allow the request to proceed.

    If role_name is 'admin' after trimming the string:
    status 422
    {
      "message": "Role name can not be admin"
    }

    If role_name is over 32 characters after trimming the string:
    status 422
    {
      "message": "Role name can not be longer than 32 chars"
    }
  */
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
