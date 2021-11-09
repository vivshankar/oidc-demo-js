// import dependencies and initialize the express router
const express = require('express');
const UserController = require('../controllers/users-controller');
const userController = new UserController();

const router = express.Router();

// define routes
router.get('/', userController.getUsersIndex);
router.get('/profile', userController.getProfile);
router.get('/consents', userController.getConsents);

module.exports = router;