const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');

dotenv.config();

// Initialize express app
const app = express();

// Middleware
app.use(cors({
  origin: true,
  methods: ['GET', 'POST', 'PATCH', 'DELETE'],
  credentials: true
}));
app.use(express.json());

// MongoDB Connection with better error handling and configuration
const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/securevault', {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      // Additional options for better connection handling
      maxPoolSize: 10, // Maintain up to 10 socket connections
      serverSelectionTimeoutMS: 5000, // Keep trying to send operations for 5 seconds
      socketTimeoutMS: 45000, // Close sockets after 45 seconds of inactivity
      bufferCommands: false, // Disable mongoose buffering
      bufferMaxEntries: 0 // Disable mongoose buffering
    });
    
    console.log(`MongoDB Connected: ${conn.connection.host}`);
    console.log(`Database Name: ${conn.connection.name}`);
  } catch (error) {
    console.error('MongoDB Connection Error:', error.message);
    process.exit(1);
  }
};

// Connect to database
connectDB();

// User Schema with enhanced validation
const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: [true, 'Username is required'],
        unique: true,
        trim: true,
        minlength: [3, 'Username must be at least 3 characters long'],
        maxlength: [50, 'Username cannot exceed 50 characters']
    },
    password: {
        type: String,
        required: [true, 'Password is required'],
        minlength: [6, 'Password must be at least 6 characters long']
    },
    passwordEntries: [{
        id: {
            type: String,
            required: true
        },
        website: {
            type: String,
            required: [true, 'Website name is required'],
            trim: true
        },
        url: {
            type: String,
            trim: true,
            default: ''
        },
        username: {
            type: String,
            required: [true, 'Username is required'],
            trim: true
        },
        password: {
            type: String,
            required: [true, 'Password is required']
        },
        notes: {
            type: String,
            default: ''
        },
        created: {
            type: Date,
            default: Date.now
        },
        lastUpdated: {
            type: Date,
            default: Date.now
        }
    }],
    createdAt: {
        type: Date,
        default: Date.now
    },
    lastLogin: {
        type: Date,
        default: Date.now
    }
});

// Index for better query performance
userSchema.index({ username: 1 });
userSchema.index({ 'passwordEntries.website': 1 });

// Create User model
const User = mongoose.model('User', userSchema);

// Authentication middleware
const auth = async (req, res, next) => {
    try {
        const authHeader = req.header('Authorization');
        if (!authHeader) {
            return res.status(401).json({ error: 'No token provided' });
        }

        const token = authHeader.replace('Bearer ', '');
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'securevaultsecret');
        
        const user = await User.findById(decoded.id);
        if (!user) {
            return res.status(401).json({ error: 'User not found' });
        }
        
        req.token = token;
        req.user = user;
        next();
    } catch (error) {
        console.error('Authentication error:', error.message);
        res.status(401).json({ error: 'Please authenticate' });
    }
};

// Register endpoint with enhanced validation
app.post('/api/users/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // Input validation
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }
        
        if (username.length < 3) {
            return res.status(400).json({ error: 'Username must be at least 3 characters long' });
        }
        
        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters long' });
        }
        
        // Check if user already exists
        const existingUser = await User.findOne({ username: username.toLowerCase() });
        if (existingUser) {
            return res.status(400).json({ error: 'Username already exists' });
        }
        
        // Hash password
        const saltRounds = 12;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Create new user
        const user = new User({
            username: username.toLowerCase(),
            password: hashedPassword,
            passwordEntries: []
        });
        
        const savedUser = await user.save();
        console.log(`New user registered: ${savedUser.username} (ID: ${savedUser._id})`);
        
        res.status(201).json({ 
            message: 'User registered successfully',
            userId: savedUser._id
        });
    } catch (error) {
        console.error('Registration error:', error);
        if (error.code === 11000) {
            return res.status(400).json({ error: 'Username already exists' });
        }
        res.status(400).json({ error: error.message });
    }
});

// Login endpoint with enhanced security
app.post('/api/users/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // Input validation
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }
        
        // Find user (case insensitive)
        const user = await User.findOne({ username: username.toLowerCase() });
        if (!user) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }
        
        // Verify password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }
        
        // Update last login
        user.lastLogin = new Date();
        await user.save();
        
        // Generate JWT token with longer expiration
        const token = jwt.sign(
            { id: user._id, username: user.username },
            process.env.JWT_SECRET || 'securevaultsecret',
            { expiresIn: '24h' }
        );
        
        console.log(`User logged in: ${user.username} (ID: ${user._id})`);
        
        res.json({
            token,
            user: {
                id: user._id,
                username: user.username,
                passwordCount: user.passwordEntries.length
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(400).json({ error: 'Login failed. Please try again.' });
    }
});

// Get user password entries
app.get('/api/passwords', auth, async (req, res) => {
    try {
        // Refresh user data from database
        const user = await User.findById(req.user._id);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        console.log(`Retrieved ${user.passwordEntries.length} password entries for user: ${user.username}`);
        res.json({ passwordEntries: user.passwordEntries });
    } catch (error) {
        console.error('Error retrieving passwords:', error);
        res.status(500).json({ error: 'Failed to retrieve password entries' });
    }
});

// Add new password entry
app.post('/api/passwords', auth, async (req, res) => {
    try {
        const { website, url, username, password, notes } = req.body;
        
        // Input validation
        if (!website || !username || !password) {
            return res.status(400).json({ error: 'Website, username, and password are required' });
        }
        
        const newEntry = {
            id: new mongoose.Types.ObjectId().toString(),
            website: website.trim(),
            url: url ? url.trim() : '',
            username: username.trim(),
            password: password,
            notes: notes ? notes.trim() : '',
            created: new Date(),
            lastUpdated: new Date()
        };
        
        // Add to user's password entries
        const user = await User.findById(req.user._id);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        user.passwordEntries.push(newEntry);
        await user.save();
        
        console.log(`New password entry added for user ${user.username}: ${newEntry.website}`);
        
        res.status(201).json({ 
            entry: newEntry,
            message: 'Password entry added successfully'
        });
    } catch (error) {
        console.error('Error adding password entry:', error);
        res.status(400).json({ error: 'Failed to add password entry' });
    }
});

// Update password entry
app.patch('/api/passwords/:id', auth, async (req, res) => {
    try {
        const { id } = req.params;
        const { website, url, username, password, notes } = req.body;
        
        // Input validation
        if (!website || !username || !password) {
            return res.status(400).json({ error: 'Website, username, and password are required' });
        }
        
        const user = await User.findById(req.user._id);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        const entryIndex = user.passwordEntries.findIndex(entry => entry.id === id);
        
        if (entryIndex === -1) {
            return res.status(404).json({ error: 'Password entry not found' });
        }
        
        // Update entry
        user.passwordEntries[entryIndex] = {
            ...user.passwordEntries[entryIndex],
            website: website.trim(),
            url: url ? url.trim() : '',
            username: username.trim(),
            password: password,
            notes: notes ? notes.trim() : '',
            lastUpdated: new Date()
        };
        
        await user.save();
        
        console.log(`Password entry updated for user ${user.username}: ${user.passwordEntries[entryIndex].website}`);
        
        res.json({ 
            entry: user.passwordEntries[entryIndex],
            message: 'Password entry updated successfully'
        });
    } catch (error) {
        console.error('Error updating password entry:', error);
        res.status(400).json({ error: 'Failed to update password entry' });
    }
});

// Delete password entry
app.delete('/api/passwords/:id', auth, async (req, res) => {
    try {
        const { id } = req.params;
        
        const user = await User.findById(req.user._id);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        const entryIndex = user.passwordEntries.findIndex(entry => entry.id === id);
        if (entryIndex === -1) {
            return res.status(404).json({ error: 'Password entry not found' });
        }
        
        const deletedEntry = user.passwordEntries[entryIndex];
        user.passwordEntries = user.passwordEntries.filter(entry => entry.id !== id);
        
        await user.save();
        
        console.log(`Password entry deleted for user ${user.username}: ${deletedEntry.website}`);
        
        res.json({ message: 'Password entry deleted successfully' });
    } catch (error) {
        console.error('Error deleting password entry:', error);
        res.status(500).json({ error: 'Failed to delete password entry' });
    }
});

// Get user statistics
app.get('/api/users/stats', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        res.json({
            username: user.username,
            totalPasswords: user.passwordEntries.length,
            memberSince: user.createdAt,
            lastLogin: user.lastLogin
        });
    } catch (error) {
        console.error('Error retrieving user stats:', error);
        res.status(500).json({ error: 'Failed to retrieve user statistics' });
    }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({
        status: 'OK',
        timestamp: new Date().toISOString(),
        database: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected'
    });
});

// Root route
app.get('/', (req, res) => {
    res.json({
        message: 'SecureVault Backend API',
        version: '1.0.0',
        endpoints: {
            register: 'POST /api/users/register',
            login: 'POST /api/users/login',
            passwords: 'GET /api/passwords',
            addPassword: 'POST /api/passwords',
            updatePassword: 'PATCH /api/passwords/:id',
            deletePassword: 'DELETE /api/passwords/:id',
            userStats: 'GET /api/users/stats',
            health: 'GET /api/health'
        }
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

// Handle 404
app.use('*', (req, res) => {
    res.status(404).json({ error: 'Route not found' });
});

// Graceful shutdown
process.on('SIGINT', async () => {
    console.log('\nShutting down gracefully...');
    await mongoose.connection.close();
    console.log('MongoDB connection closed.');
    process.exit(0);
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📊 Health check: http://localhost:${PORT}/api/health`);
    console.log(`🔒 SecureVault API: http://localhost:${PORT}`);
});
