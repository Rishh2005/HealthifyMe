const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
const PORT = process.env.PORT || 5000;
app.use(cors());
app.use(bodyParser.json());

// MongoDB connection
mongoose.connect('mongodb://localhost:27017/healthifyme', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Doctor Schema
const doctorSchema = new mongoose.Schema({
  fullName: String,
  email: { type: String, unique: true },
  phoneNo: { type: String, unique: true },
  specialization: String,
  university: String,
  password: String,
});

const Doctor = mongoose.model('Doctor', doctorSchema);

// User Schema
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  age: Number,
});

const User = mongoose.model('User', userSchema);

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ message: 'Access denied' });                      

  jwt.verify(token, 'secret_key', (err, decoded) => {
    if (err) return res.status(401).json({ message: 'Invalid token' });
    req.doctorId = decoded.id;
    next();
  });
};

// Doctor Registration
app.post('/register', async (req, res) => {
  const { fullName, email, phoneNo, specialization, university, password } = req.body;

  const hashedPassword = await bcrypt.hash(password, 10);
  const doctor = new Doctor({ fullName, email, phoneNo, specialization, university, password: hashedPassword });

  try {
    await doctor.save();
    res.status(201).json({ message: 'Doctor registered successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Error registering doctor' });
  }
});

// Doctor Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  const doctor = await Doctor.findOne({ email });
  if (!doctor) return res.status(400).json({ message: 'Doctor not found' });

  const validPassword = await bcrypt.compare(password, doctor.password);
  if (!validPassword) return res.status(400).json({ message: 'Invalid password' });

  const token = jwt.sign({ id: doctor._id }, 'secret_key');
  res.json({ token, doctor });
});

// User Registration
app.post('/api/signup', async (req, res) => {
  const { name, email, password, age } = req.body;

  try {
    const user = new User({ name, email, password, age });
    await user.save();
    res.status(201).json({ message: 'User created successfully', user });
  } catch (error) {
    res.status(500).json({ message: 'Error creating user', error });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email, password });
    if (user) {
      res.status(200).json({ message: 'Login successful', user });
    } else {
      res.status(401).json({ message: 'Invalid credentials' });
    }
  } catch (error) {
    res.status(500).json({ message: 'Error logging in', error });
  }
});

app.post('/api/google-signin', async (req, res) => {
  const { credential } = req.body;
  
  try {
    const user = new User({ name: 'Google User', email: 'google@example.com', password: 'google' });
    await user.save();
    res.status(201).json({ message: 'Google Sign-In successful', user });
  } catch (error) {
    res.status(500).json({ message: 'Error with Google Sign-In', error });
  }
});

// Start the server
app.listen(5000, () => {
  console.log('Server is running');
});