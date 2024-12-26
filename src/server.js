const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const Joi = require('joi'); // For validation
const winston = require('winston'); // For structured logging
const cookieParser = require('cookie-parser'); // To parse cookies
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const app = express();
app.use(express.json());
app.use(cookieParser()); // Use cookie parser

// Security measures
const helmet = require('helmet');
app.use(helmet({
  contentSecurityPolicy: false, // Adjust CSP as needed
}));

// Logger setup
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.Console(),
  ],
});

// Validate required environment variables
if (!process.env.JWT_SECRET || !process.env.MONGODB_URI) {
  logger.error('Critical environment variables are missing. Exiting application.');
  process.exit(1);
}

// JWT secret
const jwtSecret = process.env.JWT_SECRET;

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.redirect('/login');
  }
  try {
    const decoded = jwt.verify(token, jwtSecret);
    req.user = decoded;
    next();
  } catch (err) {
    return res.redirect('/login');
  }
};

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => logger.info('Connected to MongoDB'))
  .catch(err => {
    logger.error('MongoDB connection error:', err);
    process.exit(1);
  });

// Create User model
const User = mongoose.model('User', new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
}));

// Create Asset model
const Asset = mongoose.model('Asset', {
  barcode: { type: String, required: true },
  assetName: { type: String, required: true },
  lab: { type: String, required: true },
  date: { type: Date, required: true },
});

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, '..', 'public')));

// Request validation schemas
const signupSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
});

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required(),
});

const assetSchema = Joi.object({
  barcode: Joi.string().required(),
  assetName: Joi.string().required(),
  lab: Joi.string().required(),
  date: Joi.date().required(),
});

// Signup route
app.post('/signup', async (req, res) => {
  try {
    const { error } = signupSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ message: error.details[0].message });
    }
    const { email, password } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const user = new User({ email, password: hashedPassword });
    await user.save();
    res.status(201).json({ message: 'User created successfully' });
  } catch (error) {
    logger.error('Signup error:', error);
    res.status(500).json({ message: 'Error creating user' });
  }
});

// Login route
app.post('/login', async (req, res) => {
  try {
    const { error } = loginSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ message: error.details[0].message });
    }
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }
    const token = jwt.sign({ userId: user._id }, jwtSecret, { expiresIn: '1h' });

    // Set token in cookie
    res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production' });

    // Send success response and redirect to index
    res.json({ message: 'Logged in successfully' });
  } catch (error) {
    logger.error('Login error:', error);
    res.status(500).json({ message: 'Error logging in' });
  }
});



// Logout route
app.get('/logout', (req, res) => {
  res.clearCookie('token'); // Clear the token cookie
  res.redirect('/login');
});

// Asset submission route
app.post('/submit-asset', verifyToken, async (req, res) => {
  try {
    const { error } = assetSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ message: error.details[0].message });
    }
    const { barcode, assetName, lab, date } = req.body;
    const asset = new Asset({ barcode, assetName, lab, date });
    await asset.save();
    res.status(201).json({ message: 'Asset saved successfully' });
  } catch (error) {
    logger.error('Asset submission error:', error);
    res.status(500).json({ message: 'Error saving asset' });
  }
});

// Serve HTML files
app.get('/', (req, res) => {
  const token = req.cookies.token;
  if (token) {
    try {
      jwt.verify(token, jwtSecret);
      return res.redirect('/index');
    } catch (err) {
      res.clearCookie('token'); // Clear the invalid token
    }
  }
  res.redirect('/login'); // Redirect to login if no valid token
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'login.html'));
});

app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'signup.html'));
});

app.get('/index', verifyToken, (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

// Catch-all route
app.get('*', (req, res) => {
  res.redirect('/login');
});

// Server
const port = process.env.PORT || 3000;
app.listen(port, () => logger.info(`Server running on port ${port}`));
