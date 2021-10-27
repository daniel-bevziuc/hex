const User = require('../models/User.model');
const jwt = require('jsonwebtoken');
const validation = require('../helpers/validation');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const nodemailer = require('nodemailer');
const moment = require('moment');

const login = async (req, res) => {
  try {
    const { error } = validation.loginSchema.validate(req.body);

    if (error) {
      res.status(400).json({
        status: 400,
        message: 'INPUT_ERRORS',
        errors: error.details,
        original: error._original,
      });
    } else {
      const user = await User.findOne({ email: req.body.email });

      // Check if the email is correct
      if (user) {
        // Check if the password correct
        const validatePassword = await bcrypt.compare(req.body.password, user.password);

        if (validatePassword) {
          // Generate Access & Refresh Token
          const accessToken = jwt.sign({
            _id: user.id,
            username: user.username,
            email: user.email,
          }, process.env.SECRET_ACCESS_TOKEN, { expiresIn: process.env.ACCESS_TOKEN_EXPIRY });
          const refreshToken = jwt.sign({
            _id: user.id,
            username: user.username,
            email: user.email,
          }, process.env.SECRET_REFRESH_TOKEN, { expiresIn: process.env.REFRESH_TOKEN_EXPIRY });

          if (await addRefreshToken(user, refreshToken)) {
            res.status(200).json({
              success: {
                status: 200,
                message: 'LOGIN_SUCCESS',
                accessToken: accessToken,
                refreshToken: refreshToken,
              },
            });
          } else {
            res.status(500).json({ error: { status: 500, message: 'SERVER_ERROR' } });
          }
        } else {
          res.status(403).json({ error: { status: 403, message: 'INVALID_CREDENTIALS' } });
        }
      } else {
        res.status(403).json({ error: { status: 403, message: 'INVALID_CREDENTIALS' } });
      }
    }
  } catch (err) {
    console.log(err);
    res.status(400).json({ error: { status: 400, message: 'BAD_REQUEST' } });
  }
};

const register = async (req, res) => {
  try {
    const { error } = validation.registerSchema.validate(req.body, { abortEarly: false });

    if (error) {
      res.status(400).json({
        status: 400,
        message: 'INPUT_ERRORS',
        errors: error.details,
        original: error._original,
      });
    } else {
      // Encrypt password
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(req.body.password, salt);

      // Create new User instance
      const user = new User({
        email: req.body.email,
        password: hashedPassword,
        emailConfirmed: false,
        emailToken: uuidv4(),
        security: {
          tokens: [],
          passwordReset: {
            token: null,
            provisionalPassword: null,
            expiry: null,
          },
        },
      });

      // Attempt to save the user in database
      await user.save();

      // Generate Access & Refresh Token
      const accessToken = jwt.sign({
        _id: user.id,
        email: user.email,
      }, process.env.SECRET_ACCESS_TOKEN, { expiresIn: process.env.ACCESS_TOKEN_EXPIRY });
      const refreshToken = jwt.sign({
        _id: user.id,
        email: user.email,
      }, process.env.SECRET_REFRESH_TOKEN, { expiresIn: process.env.REFRESH_TOKEN_EXPIRY });

      // Assign the token to user and save
      await User.updateOne({ email: user.email }, {
        $push: {
          'security.tokens': {
            refreshToken: refreshToken,
            createdAt: new Date(),
          },
        },
      });

      // Send Email Confirmation
      await sendEmailConfirmation({ email: user.email, emailToken: user.emailToken });

      res.status(200).header().json({
        success: {
          status: 200,
          message: 'REGISTER_SUCCESS',
          accessToken: accessToken,
          refreshToken: refreshToken,
          user: {
            id: user.id,
            email: user.email,
          },
        },
      });
    }
  } catch (err) {
    console.log(err);
    let errorMessage;

    if (err.keyPattern.email === 1) {
      errorMessage = 'EMAIL_EXISTS';
    } else {
      errorMessage = err;
    }

    res.status(400).json({ error: { status: 400, message: errorMessage } });
  }
};

const token = async (req, res) => {
  try {
    const refreshToken = req.body.refreshToken;

    // Verify if the token is valid - if not, don't authorise, ask to re-authenticate
    try {
      const decodeRefreshToken = jwt.verify(refreshToken, process.env.SECRET_REFRESH_TOKEN);
      const user = await User.findOne({ email: decodeRefreshToken.email });
      const existingRefreshTokens = user.security.tokens;

      // Check if refresh token is in document
      if (existingRefreshTokens.some(token => token.refreshToken === refreshToken)) {

        // Generate new Access Token
        const accessToken = jwt.sign({
          _id: user.id,
          email: user.email,
        }, process.env.SECRET_ACCESS_TOKEN, { expiresIn: process.env.ACCESS_TOKEN_EXPIRY });

        // Send new Access Token
        res.status(200).json({
          success: {
            status: 200,
            message: 'ACCESS_TOKEN_GENERATED',
            accessToken: accessToken,
          },
        });
      } else {
        res.status(401).json({ error: { status: 401, message: 'INVALID_REFRESH_TOKEN' } });
      }
    } catch (err) {
      res.status(401).json({ error: { status: 401, message: 'INVALID_REFRESH_TOKEN' } });
    }
  } catch (err) {
    res.status(400).json({ error: { status: 400, message: 'BAD_REQUEST' } });
  }
};

const confirmEmailToken = async (req, res) => {
  try {
    const emailToken = req.body.emailToken;

    if (emailToken !== null) {
      const accessToken = req.header('Authorization').split(' ')[1];
      const decodedAccessToken = jwt.verify(accessToken, process.env.SECRET_ACCESS_TOKEN);

      // Check if user exists
      const user = await User.findOne({ email: decodedAccessToken.email });

      // Check if email is already confirmed
      if (!user.emailConfirmed) {
        // Check if provided email token matches user's email token
        if (emailToken === user.emailToken) {
          await User.updateOne({ email: decodedAccessToken.email }, { $set: { emailConfirmed: true, emailToken: null } });
          res.status(200).json({ success: { status: 200, message: 'EMAIL_CONFIRMED' } });
        } else {
          res.status(401).json({ error: { status: 401, message: 'INVALID_EMAIL_TOKEN' } });
        }
      } else {
        res.status(401).json({ error: { status: 401, message: 'EMAIL_ALREADY_CONFIRMED' } });
      }
    } else {
      res.status(400).json({ error: { status: 400, message: 'BAD_REQUEST' } });
    }
  } catch (err) {
    res.status(400).json({ error: { status: 400, message: 'BAD_REQUEST' } });
  }
};

const resetPasswordConfirm = async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });

    // Check if supplied passwordResetToken matches with the user's stored one
    if (user.security.passwordReset.token === req.body.passwordResetToken) {

      // Check if password reset token is expired
      if (new Date().getTime() <= new Date(user.security.passwordReset.expiry).getTime()) {
        await User.updateOne({ email: req.body.email }, {
          $set: {
            'password': user.security.passwordReset.provisionalPassword,
            'security.passwordReset.token': null,
            'security.passwordReset.provisionalPassword': null,
            'security.passwordReset.expiry': null,
          },
        });

        res.status(200).json({ success: { status: 200, message: 'PASSWORD_RESET_SUCCESS' } });
      } else {
        await User.updateOne({ email: req.body.email }, {
          $set: {
            'security.passwordReset.token': null,
            'security.passwordReset.provisionalPassword': null,
            'security.passwordReset.expiry': null,
          },
        });

        res.status(401).json({ error: { status: 401, message: 'PASSWORD_RESET_TOKEN_EXPIRED' } });
      }
    } else {
      res.status(401).json({ error: { status: 401, message: 'INVALID_PASSWORD_RESET_TOKEN' } });
    }
  } catch (err) {
    res.status(400).json({ error: { status: 400, message: 'BAD_REQUEST' } });
  }
};

const resetPassword = async (req, res) => {
  try {
    if (req.body.provisionalPassword.length >= 6 && req.body.provisionalPassword.length <= 255) {
      // Hash Password
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(req.body.provisionalPassword, salt);

      // Generate a password reset token
      const passwordResetToken = uuidv4();
      const expiresIn = moment().add(10, 'm').toISOString();

      // Update user with password token
      const user = await User.findOneAndUpdate({ email: req.body.email }, {
        $set: {
          'security.passwordReset': {
            token: passwordResetToken,
            provisionalPassword: hashedPassword,
            expiry: expiresIn,
          },
        },
      });

      await sendPasswordResetConfirmation({ email: req.body.email, passwordResetToken: passwordResetToken });

      res.status(200).json({ success: { status: 200, message: 'PASSWORD_RESET_EMAIL_SENT' } });
    } else {
      res.status(400).json({ error: { status: 400, message: 'PASSWORD_INPUT_ERROR' } });
    }
  } catch (err) {
    res.status(400).json({ error: { status: 400, message: 'BAD_REQUEST' } });
  }
};

const changeEmail = async (req, res) => {
  try {
    if (validation.emailSchema.validate({ email: req.body.provisionalEmail })) {
      // Decode Access Token
      const accessToken = req.header('Authorization').split(' ')[1];
      const decodeAccessToken = jwt.verify(accessToken, process.env.SECRET_ACCESS_TOKEN);

      // Check if email exists
      const emailExistsCheck = await User.findOne({ email: req.body.provisionalEmail });

      if (!emailExistsCheck) {
        // Generate an email confirmation token
        const changeEmailToken = uuidv4();
        const expiresIn = moment().add(10, 'm').toISOString();

        // Update user with change email token
        const user = await User.findOneAndUpdate({ email: decodeAccessToken.email }, {
          $set: {
            'security.changeEmail': {
              token: changeEmailToken,
              provisionalEmail: req.body.provisionalEmail,
              expiry: expiresIn,
            },
          },
        });

        await changeEmailConfirmation({ email: user.email, emailToken: changeEmailToken });

        res.status(200).json({ success: { status: 200, message: 'CHANGE_EMAIL_SENT' } });
      } else {
        res.status(400).json({ error: { status: 400, message: 'EMAIL_USER_REGISTERED' } });
      }
    } else {
      res.status(400).json({ error: { status: 400, message: 'EMAIL_INPUT' } });
    }
  } catch (err) {
    res.status(400).json({ error: { status: 200, message: 'BAD_REQUEST' } });
  }
};

const changeEmailConfirm = async (req, res) => {
  try {
    // Decode Access Token
    const accessToken = req.header('Authorization').split(' ')[1];
    const decodedAccessToken = jwt.verify(accessToken, process.env.SECRET_ACCESS_TOKEN);

    // Fetch user
    const user = await User.findOne({ email: decodedAccessToken.email });

    // Check if the email exists
    const emailExistsCheck = await User.findOne({ email: user.security.changeEmail.provisionalEmail });

    if (!emailExistsCheck) {
      if (user.security.changeEmail.token === req.body.changeEmailToken) {

        // Check if the change email token is not expired
        if (new Date().getTime() <= new Date(user.security.changeEmail.expiry).getTime()) {
          await User.updateOne({ email: decodedAccessToken.email }, {
            $set: {
              'email': user.security.changeEmail.provisionalEmail,
              'security.changeEmail.token': null,
              'security.changeEmail.provisionalEmail': null,
              'security.changeEmail.expiry': null,
            },
          });
          res.status(200).json({ success: { status: 200, message: 'CHANGE_EMAIL_SUCCESS' } });
        } else {
          res.status(401).json({ success: { status: 401, message: 'CHANGE_EMAIL_TOKEN_EXPIRED' } });
        }
      } else {
        res.status(401).json({ success: { status: 401, message: 'INVALID_CHANGE_EMAIL_TOKEN' } });
      }
    } else {
      await User.updateOne({ email: decodedAccessToken.email }, {
        $set: {
          'security.changeEmail.token': null,
          'security.changeEmail.provisionalEmail': null,
          'security.changeEmail.expiry': null,
        },
      });
    }
  } catch (err) {
    res.status(400).json({ error: { status: 400, message: 'BAD_REQUEST' } });
  }
};

const test = async (req, res) => {
  try {
    const newUser = new User({
      email: 'test2@test.com',
      password: 'test',
      emailConfirmed: false,
      emailToken: 'test',
      security: {
        tokens: null,
        passwordReset: null,
      },
    });

    await newUser.save();
    res.send(newUser);
  } catch (err) {
    res.send(err);
  }
};

const addRefreshToken = async (user, refreshToken) => {
  try {
    const existingRefreshTokens = user.security.tokens;

    // Check if there less than 5
    if (existingRefreshTokens.length < 5) {
      await User.updateOne({ email: user.email }, {
        $push: {
          'security.tokens': {
            refreshToken: refreshToken,
            createdAt: new Date(),
          },
        },
      });
    } else {
      // Otherwise, remove the last token
      await User.updateOne({ email: user.email }, {
        $pull: {
          'security.tokens': {
            _id: existingRefreshTokens[0]._id,
          },
        },
      });

      // Push the new token
      await User.updateOne({ email: user.email }, {
        $push: {
          'security.tokens': {
            refreshToken: refreshToken,
            createdAt: new Date(),
          },
        },
      });
    }
    return true;
  } catch (err) {
    return false;
  }
};

const changeEmailConfirmation = async (user) => {
  const transport = nodemailer.createTransport({
    host: process.env.NODEMAILER_HOST,
    port: process.env.NODEMAILER_PORT,
    auth: {
      user: process.env.NODEMAILER_USER,
      pass: process.env.NODEMAILER_PASS,
    },
  });

  const info = await transport.sendMail({
    from: '"Confirm email Test" <noreply@hexhealthcare.com>',
    to: user.email,
    subject: 'Confirm Your Email',
    text: `Click the link to confirm your new email change: http://localhost:9000/confirm-email-change/${user.emailToken}`,
  });
};

const sendEmailConfirmation = async (user) => {
  const transport = nodemailer.createTransport({
    host: process.env.NODEMAILER_HOST,
    port: process.env.NODEMAILER_PORT,
    auth: {
      user: process.env.NODEMAILER_USER,
      pass: process.env.NODEMAILER_PASS,
    },
  });

  const info = await transport.sendMail({
    from: '"Confirm email Test" <noreply@hexhealthcare.com>',
    to: user.email,
    subject: 'Confirm Your Email',
    text: `Click the link to confirm your email: http://localhost:9000/confirm-email/${user.emailToken}`,
  });
};

const sendPasswordResetConfirmation = async (user) => {
  const transport = nodemailer.createTransport({
    host: process.env.NODEMAILER_HOST,
    port: process.env.NODEMAILER_PORT,
    auth: {
      user: process.env.NODEMAILER_USER,
      pass: process.env.NODEMAILER_PASS,
    },
  });

  const info = await transport.sendMail({
    from: '"Reset email password test" <noreply@hexhealthcare.com>',
    to: user.email,
    subject: 'Reset Your Password',
    text: `Click the link to confirm your password reset: http://localhost:9000/confirm-password/${user.passwordResetToken}`,
  });
};

module.exports = { test, login, register, token, confirmEmailToken, resetPassword, resetPasswordConfirm, changeEmail, changeEmailConfirm };
