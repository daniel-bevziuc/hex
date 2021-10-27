const express = require('express');
const authController = require('../controllers/auth.controller');

// API Middleware
const rateLimiter = require('../helpers/rateLimiter');
const verifyToken = require('../helpers/verifyToken');

// Router initialisation
const router = express.Router();

router.post('/login', authController.login);
router.post('/register', authController.register);
router.post('/token', authController.token);
router.post('/confirmEmailToken', verifyToken, authController.confirmEmailToken);
router.post('/resetPassword', authController.resetPassword);
router.post('/resetPasswordConfirm', authController.resetPasswordConfirm);
router.post('/changeEmail', authController.changeEmail);
router.post('/changeEmailConfirm', authController.changeEmailConfirm);

module.exports = router;
