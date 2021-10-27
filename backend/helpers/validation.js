const Joi = require('joi');

const registerSchema = Joi.object({
  email: Joi.string().min(4).max(25).email(),
  password: Joi.string().min(6).max(255),
});

const loginSchema = Joi.object({
  email: Joi.string().min(4).max(25).email(),
  password: Joi.string().min(6).max(255),
});

const emailSchema = Joi.object({
  email: Joi.string().min(4).max(25).email(),
});

module.exports = {registerSchema, loginSchema, emailSchema};
