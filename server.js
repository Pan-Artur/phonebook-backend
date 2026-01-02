const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

if (process.env.NODE_ENV !== 'production') {
  require("dotenv").config();
}

const app = express();

const allowedOrigins = [
  'http://localhost:3000',
  'https://phonebook-frontend-beige.vercel.app'
];

// Логування для debug
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url} - Origin: ${req.headers.origin}`);
  next();
});

// CORS middleware
app.use((req, res, next) => {
  const origin = req.headers.origin;
  
  if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  
  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    console.log('Handling OPTIONS preflight request');
    return res.status(200).end(); // Важливо: 200, не 204!
  }
  
  next();
});

app.use(express.json());

let poolConfig;

if (process.env.DATABASE_URL) {
  poolConfig = {
    connectionString: process.env.DATABASE_URL,
    ssl: {
      rejectUnauthorized: false
    }
  };
} else {
  poolConfig = {
    host: 'localhost',
    port: 5432,
    database: 'phonebook',
    user: 'phonebook_user',
    password: 'password123'
  };
}

const pool = new Pool(poolConfig);

async function createTables() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(250) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )  
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS contacts (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        number VARCHAR(20) NOT NULL,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )  
    `);
  } catch (error) {
    console.error(error);
  }
}

const auth = async (req, res, next) => {
  try {
    const token = req.header("Authorization")?.replace("Bearer ", "");
    if (!token) throw new Error();

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const result = await pool.query(
      "SELECT id, name, email FROM users WHERE id = $1",
      [decoded.userId]
    );

    if (result.rows.length === 0) throw new Error();

    req.user = result.rows[0];
    next();
  } catch (error) {
    res.status(401).json({ message: "Not authorized!" });
  }
};

app.post("/users/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const userExists = await pool.query(
      "SELECT id FROM users WHERE email = $1",
      [email]
    );

    if (userExists.rows.length > 0) {
      return res.status(409).json({ message: "Email already exists!" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      "INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id, name, email",
      [name, email, hashedPassword]
    );

    const user = result.rows[0];

    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.status(201).json({
      user: {
        name: user.name,
        email: user.email,
      },
      token,
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.post("/users/login", async (req, res) => {
  try {
    console.log('=== LOGIN START ===');
    console.log('Request body:', req.body);
    
    const { email, password } = req.body;
    
    console.log('Email:', email, 'Password:', password ? '***' : 'missing');

    // 1. Перевірка вхідних даних
    if (!email || !password) {
      console.log('Missing email or password');
      return res.status(400).json({ message: "Email and password required!" });
    }

    console.log('Querying database...');
    
    // 2. Запит до бази
    const result = await pool.query(
      "SELECT id, name, email, password FROM users WHERE email = $1",
      [email]
    );

    console.log('Query result - rows found:', result.rows.length);
    
    if (result.rows.length === 0) {
      console.log('No user found with email:', email);
      return res.status(401).json({ message: "Invalid credentials!" });
    }

    const user = result.rows[0];
    console.log('User found:', user.email);
    console.log('User password hash:', user.password ? '***' : 'null');

    // 3. Перевірка пароля
    console.log('Comparing password with bcrypt...');
    console.log('bcrypt.compare exists:', typeof bcrypt.compare);
    
    const isPasswordValid = await bcrypt.compare(password, user.password);
    console.log('Password valid:', isPasswordValid);

    if (!isPasswordValid) {
      console.log('Password invalid');
      return res.status(401).json({ message: "Invalid credentials!" });
    }

    // 4. Перевірка JWT_SECRET
    console.log('JWT_SECRET exists:', !!process.env.JWT_SECRET);
    console.log('JWT_SECRET length:', process.env.JWT_SECRET?.length);
    
    if (!process.env.JWT_SECRET) {
      console.error('JWT_SECRET is not set!');
      return res.status(500).json({ message: "Server configuration error" });
    }

    // 5. Створення токена
    console.log('Creating JWT token...');
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    console.log('Token created:', token ? '***' : 'null');
    console.log('=== LOGIN SUCCESS ===');

    res.json({
      user: {
        name: user.name,
        email: user.email,
      },
      token,
    });
  } catch (error) {
    console.error('=== LOGIN ERROR ===');
    console.error('Error message:', error.message);
    console.error('Error stack:', error.stack);
    console.error('Error name:', error.name);
    console.error('Full error:', error);
    
    res.status(500).json({ 
      message: "Internal server error",
      error: error.message 
    });
  }
});

app.get("/contacts", auth, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, name, number FROM contacts WHERE user_id = $1 ORDER BY created_at DESC",
      [req.user.id]
    );

    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.post("/contacts", auth, async (req, res) => {
  try {
    const { name, number } = req.body;

    const result = await pool.query(
      "INSERT INTO contacts (name, number, user_id) VALUES ($1, $2, $3) RETURNING id, name, number",
      [name, number, req.user.id]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.delete("/contacts/:id", auth, async (req, res) => {
  try {
    const result = await pool.query(
      "DELETE FROM contacts WHERE id = $1 AND user_id = $2 RETURNING id",
      [req.params.id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Contact not found!" });
    }

    res.json({ id: req.params.id });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.post("/users/logout", (req, res) => {
  res.json({ message: "Logged out successfully!" });
});

app.get('/', (req, res) => {
  res.json({ 
    message: 'Phonebook API is running!',
    version: '1.0.0',
    status: 'OK'
  });
});

app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'OK', 
    database: 'connected'
  });
});

const PORT = process.env.PORT || 3001;

createTables().then(() => {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Available endpoints:`);
    console.log(`- POST   http://localhost:${PORT}/users/signup`);
    console.log(`- POST   http://localhost:${PORT}/users/login`);
    console.log(`- GET    http://localhost:${PORT}/users/current`);
    console.log(`- GET    http://localhost:${PORT}/contacts`);
    console.log(`- POST   http://localhost:${PORT}/contacts`);
    console.log(`- DELETE http://localhost:${PORT}/contacts/:id`);
  });
});