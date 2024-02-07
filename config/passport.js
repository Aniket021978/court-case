//creating local strategy
const LocalStrategy = require('passport-local').Strategy;
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

//load User model
const User = require('../models/User');

module.exports = (passport) => {
    passport.use(new LocalStrategy({
        usernameField: 'email'
    }, (email, password, done) => {
        // match user
        User.findOne({
            email: email
        }).then((user) => {
            if (!user) {
                return done(null, false, {
                    message: 'That e-mail is not registered...'
                });
            }

            console.log("Retrieved user:", user);

            // Ensure that the user object has the expected password property
            if (!user.password) {
                return done(null, false, {
                    message: 'User does not have a password set...'
                });
            }

            // Match password using bcrypt
            bcrypt.compare(password, user.password, (err, isMatch) => {
                if (err) {
                    throw err;
                }
                if (isMatch) {
                    return done(null, user);
                } else {
                    return done(null, false, {
                        message: 'Password incorrect...'
                    });
                }
            });
        }).catch((err) => {
            console.log(err);
            return done(err);
        });
    }));

    // methods to serialize and de-serialize user
    passport.serializeUser((user, done) => {
        done(null, user.id);
    });

    passport.deserializeUser((id, done) => {
        User.findById(id, (err, user) => {
            done(err, user);
        });
    });
};
