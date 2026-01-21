// Ensure environment variables are available
if (!process.env.DB_HOST && !process.env.NODE_ENV) {
  console.log('⚠️ Warning: Environment variables not loaded. Attempting to load .env file...');
  import('dotenv').then(dotenv => {
    dotenv.config({ path: '../.env' });
    dotenv.config({ path: '../.env.production' });
  }).catch(err => {
    console.error('Failed to load dotenv:', err);
  });
}

console.log('🔧 Database Configuration Debug:');
console.log('  NODE_ENV:', process.env.NODE_ENV || 'development');
console.log('  DB_HOST:', process.env.DB_HOST || 'localhost (default)');
console.log('  DB_USER:', process.env.DB_USER || 'root');
console.log('  DB_PASSWORD:', process.env.DB_PASSWORD ? process.env.DB_PASSWORD.substring(0, 3) + '***' : 'NOT SET - using fallback');
console.log('  DB_NAME:', process.env.DB_NAME || 'cyber_security_leave_portal');
console.log('  DB_PORT:', process.env.DB_PORT || '3307');

// ===============================================
// DATABASE CONFIGURATION
// ===============================================
// For development/testing: Use local database
// For production: Uncomment the production config below

// LOCAL DEVELOPMENT DATABASE CONFIG (ACTIVE)
export const dbConfig = {
  host: 'localhost',
  user: 'root',
  password: 'Ace_cs@2025', // Your local MySQL password
  database: 'cyber_security_leave_portal',
  port: parseInt(process.env.DB_PORT) || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  acquireTimeout: 60000,
  timeout: 60000,
  reconnect: true,
  queueLimit: 0,
  charset: 'utf8mb4',
  timezone: '+00:00'
};

// PRODUCTION DATABASE CONFIG (COMMENTED OUT)
// Uncomment this and comment out the local config above when deploying to production
/*
export const dbConfig = {
  host: process.env.DB_HOST || '210.212.246.131', // Production IP
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || 'Ace_cs@2025',
  database: process.env.DB_NAME || 'cyber_security_leave_portal',
  port: parseInt(process.env.DB_PORT) || 3307, // Production port
  waitForConnections: true,
  connectionLimit: 10,
  acquireTimeout: 60000,
  timeout: 60000,
  reconnect: true,
  queueLimit: 0,
  charset: 'utf8mb4',
  timezone: '+00:00'
};
*/

export const jwtSecret = process.env.JWT_SECRET || 'your_super_secret_jwt_key_change_this_in_production';
