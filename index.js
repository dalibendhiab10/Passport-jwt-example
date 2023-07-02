const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const Sequelize = require('sequelize');
const app = express();
const secretKeyJwt = 'daliyam';

const sequelize = new Sequelize('jatexpress', 'root', '', {
  host: 'localhost',
  dialect: 'mysql'
});

const User = sequelize.define('User', {
  username: {
    type: Sequelize.STRING,
    allowNull: false,
    unique: true
  },
  password: {
    type: Sequelize.STRING,
    allowNull: false
  }
});

passport.use(new LocalStrategy(
  async (username, password, done) => {
    try {
      if( username=="dali"){
        return done(null, username);

      }
      else{
        return done("mch mawjoud");

      }
      // const user = await User.findOne({ where: { username } });
      // if (!user) {
      //   return done(null, false, { message: 'Incorrect username.' });
      // }
      // if (user.password !== password) {
      //   return done(null, false, { message: 'Incorrect password.' });
      // }
    } catch (error) {
      return done(error);
    }
  }
));

const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: secretKeyJwt
};

passport.use(new JwtStrategy(jwtOptions, (jwtPayload, done) => {
  User.findByPk(jwtPayload.id)
    .then(user => {
      if (user) {
        return done(null, user);
      } else {
        return done(null, false);
      }
    })
    .catch(error => {
      return done(error);
    });
}));

app.use(bodyParser.json());

app.post('/login', (req, res, next) => {
  passport.authenticate('local', { session: false }, (err, user, info) => {
    if (err) {
      return next(err);
    }
    if (!user) {
      return res.status(401).json({ message: info.message });
    }

    const token = jwt.sign({ id: user.id }, jwtOptions.secretOrKey);
    return res.json({ token });
  })(req, res, next);
});

app.get('/fetch', passport.authenticate('jwt', { session: false }), (req, res) => {
  const token = req.headers.authorization.split(' ')[1];
  const decoded = jwt.verify(token, secretKeyJwt);
  const userId = decoded.id;
  res.json({ message: 'Success: You are authorized to access this route.' , userId: `User ID: ${userId}`});
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
