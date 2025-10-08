import express from 'express';
import cors from 'cors';
import * as dotenv from 'dotenv';
import * as path from 'path';
import * as fs from 'fs';
import { PGlite } from '@electric-sql/pglite';
import { fileURLToPath } from 'url';
import jwt from 'jsonwebtoken';
import morgan from 'morgan';
import { v4 as uuidv4 } from 'uuid';

// Import zod schemas
import { 
  userSchema, 
  createUserInputSchema, 
  updateUserInputSchema, 
  calculationSchema,
  createCalculationInputSchema,
  updateCalculationInputSchema,
  settingSchema,
  createSettingInputSchema,
  updateSettingInputSchema
} from './schema.ts';

dotenv.config();

// ESM workaround for __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Error response utility
interface ErrorResponse {
  success: false;
  message: string;
  error_code?: string;
  details?: any;
  timestamp: string;
}

function createErrorResponse(
  message: string,
  error?: any,
  errorCode?: string
): ErrorResponse {
  const response: ErrorResponse = {
    success: false,
    message,
    timestamp: new Date().toISOString()
  };

  if (errorCode) {
    response.error_code = errorCode;
  }

  if (error) {
    response.details = {
      name: error.name,
      message: error.message,
      stack: error.stack
    };
  }

  return response;
}

// Environment variables and database setup
const { 
  JWT_SECRET = 'your-secret-key',
  PORT = 3000
} = process.env;

// Use PGlite for local development (embedded PostgreSQL)
const db = new PGlite('./data');

const app = express();

// Initialize database with schema
async function initializeDatabase() {
  try {
    // Read and execute the SQL schema
    const schemaPath = path.join(__dirname, 'db.sql');
    const schema = fs.readFileSync(schemaPath, 'utf-8');
    await db.exec(schema);
    console.log('Database initialized successfully');
  } catch (error) {
    console.error('Database initialization error:', error);
  }
}

// Initialize database on startup
initializeDatabase();

// Middleware setup
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:5173',
  credentials: true,
}));

app.use(express.json({ limit: "5mb" }));
app.use(morgan('combined')); // Request logging

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

/*
  Auth middleware for protected routes
  Validates JWT token and attaches user info to request
*/
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json(createErrorResponse('Access token required', null, 'TOKEN_MISSING'));
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const result = await db.query(
      'SELECT user_id, email, is_active, created_at, updated_at FROM users WHERE user_id = $1', 
      [decoded.user_id]
    );
    
    if (result.rows.length === 0) {
      return res.status(401).json(createErrorResponse('Invalid token - user not found', null, 'USER_NOT_FOUND'));
    }

    const user = result.rows[0];
    if (!user.is_active) {
      return res.status(401).json(createErrorResponse('Account is inactive', null, 'ACCOUNT_INACTIVE'));
    }

    req.user = user;
    next();
  } catch (error) {
    return res.status(403).json(createErrorResponse('Invalid or expired token', error, 'AUTH_TOKEN_INVALID'));
  }
};

// AUTH ENDPOINTS

/*
  User registration endpoint
  Creates new user account and returns JWT token
*/
app.post('/api/auth/register', async (req, res) => {
  try {
    // Validate request body using zod schema
    const validatedData = createUserInputSchema.parse(req.body);
    const { email, password_hash } = validatedData;

    // Check if user already exists
    const existingUser = await db.query('SELECT user_id FROM users WHERE email = $1', [email.toLowerCase().trim()]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json(createErrorResponse('User with this email already exists', null, 'USER_ALREADY_EXISTS'));
    }

    // Create new user (no password hashing for development)
    const userId = uuidv4();
    const now = Date.now();
    
    const result = await db.query(
      `INSERT INTO users (user_id, email, password_hash, is_active, created_at, updated_at) 
       VALUES ($1, $2, $3, $4, $5, $6) 
       RETURNING user_id, email, is_active, created_at, updated_at`,
      [userId, email.toLowerCase().trim(), password_hash, true, now, now]
    );

    const user = result.rows[0];

    // Generate JWT token
    const token = jwt.sign(
      { user_id: user.user_id, email: user.email }, 
      JWT_SECRET, 
      { expiresIn: '7d' }
    );

    res.status(201).json({
      message: 'User created successfully',
      user: {
        id: user.user_id,
        email: user.email,
        name: user.email.split('@')[0], // Extract name from email
        created_at: new Date(user.created_at).toISOString()
      },
      token
    });
  } catch (error) {
    console.error('Registration error:', error);
    if (error.name === 'ZodError') {
      return res.status(400).json(createErrorResponse('Invalid input data', error, 'VALIDATION_ERROR'));
    }
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

/*
  Token verification endpoint
  Validates JWT token and returns user info
*/
app.get('/api/auth/verify', authenticateToken, async (req, res) => {
  try {
    const user = req.user;
    
    res.json({
      message: 'Token is valid',
      user: {
        id: user.user_id,
        email: user.email,
        name: user.email.split('@')[0], // Extract name from email
        created_at: new Date(user.created_at).toISOString()
      }
    });
  } catch (error) {
    console.error('Token verification error:', error);
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

// USER MANAGEMENT ENDPOINTS

/*
  Get user profile by user_id
  Returns user information for authenticated requests
*/
app.get('/api/users/:user_id', authenticateToken, async (req, res) => {
  try {
    const { user_id } = req.params;

    // Check if user is accessing their own profile or has admin privileges
    if (req.user.user_id !== user_id) {
      return res.status(403).json(createErrorResponse('Access denied - can only view own profile', null, 'ACCESS_DENIED'));
    }

    const result = await db.query(
      'SELECT user_id, email, is_active, created_at, updated_at FROM users WHERE user_id = $1',
      [user_id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json(createErrorResponse('User not found', null, 'USER_NOT_FOUND'));
    }

    const user = result.rows[0];

    res.json({
      user: {
        id: user.user_id,
        email: user.email,
        name: user.email.split('@')[0],
        created_at: new Date(user.created_at).toISOString()
      }
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

/*
  Update user profile
  Allows users to update their email, password, or active status
*/
app.put('/api/users/:user_id', authenticateToken, async (req, res) => {
  try {
    const { user_id } = req.params;

    // Check if user is updating their own profile
    if (req.user.user_id !== user_id) {
      return res.status(403).json(createErrorResponse('Access denied - can only update own profile', null, 'ACCESS_DENIED'));
    }

    // Validate request body
    const validatedData = updateUserInputSchema.parse({ user_id, ...req.body });

    const updateFields = [];
    const updateValues = [];
    let paramCount = 1;

    // Build dynamic update query
    if (validatedData.email) {
      updateFields.push(`email = $${paramCount}`);
      updateValues.push(validatedData.email.toLowerCase().trim());
      paramCount++;
    }

    if (validatedData.password_hash) {
      updateFields.push(`password_hash = $${paramCount}`);
      updateValues.push(validatedData.password_hash);
      paramCount++;
    }

    if (validatedData.is_active !== undefined) {
      updateFields.push(`is_active = $${paramCount}`);
      updateValues.push(validatedData.is_active);
      paramCount++;
    }

    if (updateFields.length === 0) {
      return res.status(400).json(createErrorResponse('No valid fields to update', null, 'NO_UPDATE_FIELDS'));
    }

    // Add updated_at timestamp
    updateFields.push(`updated_at = $${paramCount}`);
    updateValues.push(Date.now());
    paramCount++;

    // Add user_id for WHERE clause
    updateValues.push(user_id);

    const query = `
      UPDATE users 
      SET ${updateFields.join(', ')} 
      WHERE user_id = $${paramCount}
      RETURNING user_id, email, is_active, created_at, updated_at
    `;

    const result = await db.query(query, updateValues);

    if (result.rows.length === 0) {
      return res.status(404).json(createErrorResponse('User not found', null, 'USER_NOT_FOUND'));
    }

    const user = result.rows[0];

    res.json({
      message: 'Profile updated successfully',
      user: {
        id: user.user_id,
        email: user.email,
        name: user.email.split('@')[0],
        created_at: new Date(user.created_at).toISOString()
      }
    });
  } catch (error) {
    console.error('Update user error:', error);
    if (error.name === 'ZodError') {
      return res.status(400).json(createErrorResponse('Invalid input data', error, 'VALIDATION_ERROR'));
    }
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

// CALCULATION ENDPOINTS

/*
  Create calculation record
  Stores calculation details including input, operation, result, and device info
*/
app.post('/api/calculations', authenticateToken, async (req, res) => {
  try {
    // Validate request body with more flexible parsing
    const validatedData = createCalculationInputSchema.parse({
      input_value: req.body.input_value || null,
      operation: req.body.operation || null,
      result: req.body.result || null,
      device_type: req.body.device_type || null,
      device_id: req.body.device_id || null,
      error_message: req.body.error_message || null,
      user_agent: req.body.user_agent || req.headers['user-agent'] || null
    });

    const calculationId = uuidv4();
    const now = Date.now();

    const result = await db.query(
      `INSERT INTO calculations 
       (calculation_id, input_value, operation, result, created_at, updated_at, device_type, device_id, error_message, user_agent) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) 
       RETURNING *`,
      [
        calculationId,
        validatedData.input_value,
        validatedData.operation,
        validatedData.result,
        now,
        now,
        validatedData.device_type,
        validatedData.device_id,
        validatedData.error_message,
        validatedData.user_agent
      ]
    );

    const calculation = result.rows[0];

    res.status(201).json({
      message: 'Calculation recorded successfully',
      calculation: {
        calculation_id: calculation.calculation_id,
        input_value: calculation.input_value,
        operation: calculation.operation,
        result: calculation.result,
        created_at: new Date(calculation.created_at).toISOString(),
        updated_at: new Date(calculation.updated_at).toISOString(),
        device_type: calculation.device_type,
        device_id: calculation.device_id,
        error_message: calculation.error_message,
        user_agent: calculation.user_agent
      }
    });
  } catch (error) {
    console.error('Create calculation error:', error);
    if (error.name === 'ZodError') {
      return res.status(400).json(createErrorResponse('Invalid input data', error, 'VALIDATION_ERROR'));
    }
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

/*
  User login endpoint
  Authenticates user credentials and returns JWT token
*/
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json(createErrorResponse('Email and password are required', null, 'MISSING_REQUIRED_FIELDS'));
    }

    // Find user by email (direct password comparison for development)
    const result = await db.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase().trim()]);
    if (result.rows.length === 0) {
      return res.status(400).json(createErrorResponse('Invalid email or password', null, 'INVALID_CREDENTIALS'));
    }

    const user = result.rows[0];

    // Check if account is active
    if (!user.is_active) {
      return res.status(400).json(createErrorResponse('Account is inactive', null, 'ACCOUNT_INACTIVE'));
    }

    // Direct password comparison (no hashing for development)
    if (password !== user.password_hash) {
      return res.status(400).json(createErrorResponse('Invalid email or password', null, 'INVALID_CREDENTIALS'));
    }

    // Generate JWT token
    const token = jwt.sign(
      { user_id: user.user_id, email: user.email }, 
      JWT_SECRET, 
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Login successful',
      user: {
        id: user.user_id,
        email: user.email,
        name: user.email.split('@')[0], // Extract name from email
        created_at: new Date(user.created_at).toISOString()
      },
      token
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

/*
  Token verification endpoint
  Validates JWT token and returns user info
*/
app.get('/api/calculations/:calculation_id', authenticateToken, async (req, res) => {
  try {
    const { calculation_id } = req.params;

    const result = await db.query(
      'SELECT * FROM calculations WHERE calculation_id = $1',
      [calculation_id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json(createErrorResponse('Calculation not found', null, 'CALCULATION_NOT_FOUND'));
    }

    const calculation = result.rows[0];

    res.json({
      calculation: {
        calculation_id: calculation.calculation_id,
        input_value: calculation.input_value,
        operation: calculation.operation,
        result: calculation.result,
        created_at: new Date(calculation.created_at).toISOString(),
        updated_at: calculation.updated_at ? new Date(calculation.updated_at).toISOString() : null,
        device_type: calculation.device_type,
        device_id: calculation.device_id,
        error_message: calculation.error_message,
        user_agent: calculation.user_agent
      }
    });
  } catch (error) {
    console.error('Get calculation error:', error);
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

/*
  Update calculation record
  Allows modification of calculation details
*/
app.put('/api/calculations/:calculation_id', authenticateToken, async (req, res) => {
  try {
    const { calculation_id } = req.params;

    // Validate request body
    const validatedData = updateCalculationInputSchema.parse({ calculation_id, ...req.body });

    const updateFields = [];
    const updateValues = [];
    let paramCount = 1;

    // Build dynamic update query
    const fieldsToUpdate = ['input_value', 'operation', 'result', 'device_type', 'device_id', 'error_message', 'user_agent'];
    
    fieldsToUpdate.forEach(field => {
      if (validatedData[field] !== undefined) {
        updateFields.push(`${field} = $${paramCount}`);
        updateValues.push(validatedData[field]);
        paramCount++;
      }
    });

    if (updateFields.length === 0) {
      return res.status(400).json(createErrorResponse('No valid fields to update', null, 'NO_UPDATE_FIELDS'));
    }

    // Add updated_at timestamp
    updateFields.push(`updated_at = $${paramCount}`);
    updateValues.push(Date.now());
    paramCount++;

    // Add calculation_id for WHERE clause
    updateValues.push(calculation_id);

    const query = `
      UPDATE calculations 
      SET ${updateFields.join(', ')} 
      WHERE calculation_id = $${paramCount}
      RETURNING *
    `;

    const result = await db.query(query, updateValues);

    if (result.rows.length === 0) {
      return res.status(404).json(createErrorResponse('Calculation not found', null, 'CALCULATION_NOT_FOUND'));
    }

    const calculation = result.rows[0];

    res.json({
      message: 'Calculation updated successfully',
      calculation: {
        calculation_id: calculation.calculation_id,
        input_value: calculation.input_value,
        operation: calculation.operation,
        result: calculation.result,
        created_at: new Date(calculation.created_at).toISOString(),
        updated_at: new Date(calculation.updated_at).toISOString(),
        device_type: calculation.device_type,
        device_id: calculation.device_id,
        error_message: calculation.error_message,
        user_agent: calculation.user_agent
      }
    });
  } catch (error) {
    console.error('Update calculation error:', error);
    if (error.name === 'ZodError') {
      return res.status(400).json(createErrorResponse('Invalid input data', error, 'VALIDATION_ERROR'));
    }
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

// SETTINGS ENDPOINTS

/*
  Create user settings
  Stores user preferences like theme and button size
*/
app.post('/api/settings', authenticateToken, async (req, res) => {
  try {
    // Validate request body
    const validatedData = createSettingInputSchema.parse(req.body);

    // Ensure user can only create settings for themselves
    if (validatedData.user_id !== req.user.user_id) {
      return res.status(403).json(createErrorResponse('Access denied - can only create own settings', null, 'ACCESS_DENIED'));
    }

    // Check if settings already exist for this user
    const existingSettings = await db.query('SELECT setting_id FROM settings WHERE user_id = $1', [validatedData.user_id]);
    if (existingSettings.rows.length > 0) {
      return res.status(400).json(createErrorResponse('Settings already exist for this user', null, 'SETTINGS_ALREADY_EXIST'));
    }

    const settingId = uuidv4();
    const now = Date.now();

    const result = await db.query(
      `INSERT INTO settings (setting_id, user_id, theme, button_size, created_at, updated_at) 
       VALUES ($1, $2, $3, $4, $5, $6) 
       RETURNING *`,
      [settingId, validatedData.user_id, validatedData.theme, validatedData.button_size, now, now]
    );

    const setting = result.rows[0];

      res.status(201).json({
        message: 'Settings created successfully',
        setting: {
          setting_id: setting.setting_id,
          user_id: setting.user_id,
          theme: setting.theme,
          button_size: setting.button_size,
          created_at: new Date(setting.created_at).toISOString(),
          updated_at: new Date(setting.updated_at).toISOString()
        }
      });
  } catch (error) {
    console.error('Create settings error:', error);
    if (error.name === 'ZodError') {
      return res.status(400).json(createErrorResponse('Invalid input data', error, 'VALIDATION_ERROR'));
    }
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

/*
  Get user settings by setting_id
  Retrieves user preference settings
*/
app.get('/api/settings/:setting_id', authenticateToken, async (req, res) => {
  try {
    const { setting_id } = req.params;

    const result = await db.query(
      'SELECT * FROM settings WHERE setting_id = $1',
      [setting_id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json(createErrorResponse('Settings not found', null, 'SETTINGS_NOT_FOUND'));
    }

    const setting = result.rows[0];

    // Check if user owns these settings
    if (setting.user_id !== req.user.user_id) {
      return res.status(403).json(createErrorResponse('Access denied - can only view own settings', null, 'ACCESS_DENIED'));
    }

    res.json({
      setting: {
        setting_id: setting.setting_id,
        user_id: setting.user_id,
        theme: setting.theme,
        button_size: setting.button_size,
        created_at: new Date(setting.created_at).toISOString(),
        updated_at: setting.updated_at ? new Date(setting.updated_at).toISOString() : null
      }
    });
  } catch (error) {
    console.error('Get settings error:', error);
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

/*
  Update user settings
  Allows modification of user preferences
*/
app.put('/api/settings/:setting_id', authenticateToken, async (req, res) => {
  try {
    const { setting_id } = req.params;

    // Validate request body
    const validatedData = updateSettingInputSchema.parse({ setting_id, ...req.body });

    // Check if settings exist and user owns them
    const existingSettings = await db.query('SELECT * FROM settings WHERE setting_id = $1', [setting_id]);
    if (existingSettings.rows.length === 0) {
      return res.status(404).json(createErrorResponse('Settings not found', null, 'SETTINGS_NOT_FOUND'));
    }

    const currentSettings = existingSettings.rows[0];
    if (currentSettings.user_id !== req.user.user_id) {
      return res.status(403).json(createErrorResponse('Access denied - can only update own settings', null, 'ACCESS_DENIED'));
    }

    const updateFields = [];
    const updateValues = [];
    let paramCount = 1;

    // Build dynamic update query
    if (validatedData.theme !== undefined) {
      updateFields.push(`theme = $${paramCount}`);
      updateValues.push(validatedData.theme);
      paramCount++;
    }

    if (validatedData.button_size !== undefined) {
      updateFields.push(`button_size = $${paramCount}`);
      updateValues.push(validatedData.button_size);
      paramCount++;
    }

    if (updateFields.length === 0) {
      return res.status(400).json(createErrorResponse('No valid fields to update', null, 'NO_UPDATE_FIELDS'));
    }

    // Add updated_at timestamp
    updateFields.push(`updated_at = $${paramCount}`);
    updateValues.push(Date.now());
    paramCount++;

    // Add setting_id for WHERE clause
    updateValues.push(setting_id);

    const query = `
      UPDATE settings 
      SET ${updateFields.join(', ')} 
      WHERE setting_id = $${paramCount}
      RETURNING *
    `;

    const result = await db.query(query, updateValues);

    const setting = result.rows[0];

    res.json({
      message: 'Settings updated successfully',
      setting: {
        setting_id: setting.setting_id,
        user_id: setting.user_id,
        theme: setting.theme,
        button_size: setting.button_size,
        created_at: new Date(setting.created_at).toISOString(),
        updated_at: new Date(setting.updated_at).toISOString()
      }
    });
  } catch (error) {
    console.error('Update settings error:', error);
    if (error.name === 'ZodError') {
      return res.status(400).json(createErrorResponse('Invalid input data', error, 'VALIDATION_ERROR'));
    }
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

// UTILITY ENDPOINTS

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok',
    timestamp: new Date().toISOString(),
    service: 'a-calculator-backend'
  });
});

// SPA catch-all: serve index.html for non-API routes only
app.get(/^(?!\/api).*/, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

export { app, db };

// Start the server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT} and listening on 0.0.0.0`);
});