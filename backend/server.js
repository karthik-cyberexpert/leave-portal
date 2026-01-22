import mysql from 'mysql2/promise';
import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';
import cron from 'node-cron';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import XLSX from 'xlsx';
import csv from 'csv-parser';
import { dbConfig, jwtSecret } from './config/database.js';
import { sendLoginNotification } from './utils/loginEmailService.js';
import { testEmailConnection, sendTestEmail } from './utils/emailService.js';

// ES module path resolution
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load environment variables from .env file
dotenv.config({ path: path.resolve(__dirname, '../.env') });

// Debug environment loading
console.log('Environment loading debug:');
console.log('  .env path:', path.resolve(__dirname, '../.env'));
console.log('  NODE_ENV:', process.env.NODE_ENV || 'not set');
console.log('  DB_PASSWORD loaded:', process.env.DB_PASSWORD ? '[SET]' : '[NOT SET]');
if (process.env.DB_PASSWORD) {
  console.log('  DB_PASSWORD value:', process.env.DB_PASSWORD.substring(0, 3) + '***');
}

// Create uploads directories if they don't exist
const uploadsDir = path.join(__dirname, 'uploads', 'profile-photos');
const certificatesDir = path.join(__dirname, 'uploads', 'certificates');
const odPhotosDir = path.join(__dirname, 'uploads', 'od-photos');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}
if (!fs.existsSync(certificatesDir)) {
  fs.mkdirSync(certificatesDir, { recursive: true });
}
if (!fs.existsSync(odPhotosDir)) {
  fs.mkdirSync(odPhotosDir, { recursive: true });
}

// Import Sharp for image processing (ES module)
import sharp from 'sharp';

// Configure multer for profile photo uploads
const profilePhotoStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const fileExtension = path.extname(file.originalname);
    cb(null, file.fieldname + '-' + uniqueSuffix + fileExtension);
  }
});

// Utility function to convert images to JPG and save as profile.jpg
async function processAndSaveProfileImage(tempFilePath, userProfileDir) {
  const finalFilePath = path.join(userProfileDir, 'profile.jpg');
  await sharp(tempFilePath)
    .jpeg({ quality: 90 })
    .toFile(finalFilePath);
  fs.unlinkSync(tempFilePath); // Remove the temp file
  return finalFilePath;
}

// Simple certificate storage - we'll handle directory creation in the route
const certificateStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    // Use a temporary directory, we'll move the file later
    cb(null, certificatesDir);
  },
  filename: (req, file, cb) => {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const fileExtension = path.extname(file.originalname);
    const originalName = path.basename(file.originalname, fileExtension);
    cb(null, `certificate-${timestamp}-${originalName}${fileExtension}`);
  }
});

const fileFilter = (req, file, cb) => {
  // Accept image files and PDFs for certificates
  if (file.mimetype.startsWith('image/') || file.mimetype === 'application/pdf') {
    cb(null, true);
  } else {
    cb(new Error('Only image files and PDFs are allowed!'), false);
  }
};

// Create separate multer instances for different upload types
const profileUpload = multer({ 
  storage: profilePhotoStorage,
  fileFilter: fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB limit
  }
});

const certificateUpload = multer({ 
  storage: certificateStorage,
  fileFilter: fileFilter,
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB limit for certificates
  }
});

// Configure multer for bulk file uploads (CSV/XLSX)
const bulkUploadStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    const tempDir = path.join(__dirname, 'temp');
    if (!fs.existsSync(tempDir)) {
      fs.mkdirSync(tempDir, { recursive: true });
    }
    cb(null, tempDir);
  },
  filename: (req, file, cb) => {
    const timestamp = Date.now();
    cb(null, `bulk-upload-${timestamp}-${file.originalname}`);
  }
});

const bulkFileFilter = (req, file, cb) => {
  // Accept CSV and Excel files
  const allowedMimes = [
    'text/csv',
    'application/csv',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
  ];
  
  if (allowedMimes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Only CSV and Excel files are allowed!'), false);
  }
};

const bulkUpload = multer({
  storage: bulkUploadStorage,
  fileFilter: bulkFileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB limit for bulk upload files
  }
});

// Configure multer for OD photo uploads
const odPhotoStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, odPhotosDir);
  },
  filename: (req, file, cb) => {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const fileExtension = path.extname(file.originalname);
    const originalName = path.basename(file.originalname, fileExtension);
    cb(null, `od-photo-${timestamp}-${originalName}${fileExtension}`);
  }
});

const odPhotoFilter = (req, file, cb) => {
  // Accept only image files for OD photos
  if (file.mimetype.startsWith('image/')) {
    cb(null, true);
  } else {
    cb(new Error('Only image files are allowed for OD photos!'), false);
  }
};

const odPhotoUpload = multer({
  storage: odPhotoStorage,
  fileFilter: odPhotoFilter,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB limit for OD photos
  }
});

const app = express();
// Dynamic CORS configuration for development/production
function buildCorsOrigins() {
  const publicIp = process.env.PUBLIC_IP || process.env.DOMAIN || process.env.SERVER_IP || 'localhost';
  const protocol = process.env.ACCESS_PROTOCOL || 'http';
  const frontendPort = process.env.FRONTEND_PORT || '8085';
  const backendPort = process.env.BACKEND_PORT || process.env.PORT || '3008';
  
  const origins = [
    `${protocol}://${publicIp}:${frontendPort}`,
    `${protocol}://${publicIp}:${backendPort}`,
    `${protocol}://${publicIp}`,
    // Development origins
    'http://localhost:8085',
    'http://localhost:3008',
    'http://localhost:3009',
    'http://127.0.0.1:8085',
    'http://127.0.0.1:3008',
    'http://127.0.0.1:3009',
    // Local network
    'http://192.168.46.89:8085',
    'http://192.168.46.89:3008'
  ];
  
  // If CORS_ORIGIN is explicitly set, use it as additional origins
  if (process.env.CORS_ORIGIN) {
    origins.push(...process.env.CORS_ORIGIN.split(',').map(origin => origin.trim()));
  }
  
  // Remove duplicates
  return [...new Set(origins)];
}

const corsOptions = {
  origin: function (origin, callback) {
    // In development, allow requests with no origin (mobile apps, curl, etc.)
    if (!origin) return callback(null, true);
    
    const allowedOrigins = buildCorsOrigins();
    
    // Check if origin is allowed
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.warn(`CORS: Blocked request from origin: ${origin}`);
      console.log(`CORS: Allowed origins:`, allowedOrigins.slice(0, 10)); // Show first 10 for debugging
      // In development, be more lenient
      if (process.env.NODE_ENV !== 'production') {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS policy'));
      }
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
};

app.use(cors(corsOptions));

// IMPORTANT: Don't use express.json() globally as it can interfere with file uploads
// We'll add it selectively to non-file-upload routes

// Gravatar utility functions
function getGravatarUrl(email, size = 200) {
  if (!email) return null;
  
  // Convert email to lowercase and trim whitespace
  const normalizedEmail = email.toLowerCase().trim();
  
  // Create MD5 hash of the email
  const hash = crypto.createHash('md5').update(normalizedEmail).digest('hex');
  
  // Build Gravatar URL with identicon as default
  return `https://www.gravatar.com/avatar/${hash}?s=${size}&d=identicon&r=g`;
}

function getBestProfilePicture(customImageUrl, email, size = 200) {
  // First priority: custom uploaded image
  if (customImageUrl) {
    return customImageUrl;
  }
  
  // Second priority: Gravatar
  if (email) {
    return getGravatarUrl(email, size);
  }
  
  // No profile picture available
  return null;
}

// Serve uploaded files statically
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Certificate preview endpoint (for inline viewing)
app.get('/api/certificate/:requestId/preview', authenticateToken, async (req, res) => {
  try {
    const { requestId } = req.params;
    
    // Verify the OD request exists and the user has permission to view it
    const [odRequest] = await query('SELECT * FROM od_requests WHERE id = ?', [requestId]);
    if (!odRequest) {
      return res.status(404).json({ error: 'OD request not found' });
    }
    
    // Get user info to check permissions
    const [user] = await query('SELECT is_admin, is_tutor FROM users WHERE id = ?', [req.user.id]);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Check if user has permission to view this certificate
    const canView = user.is_admin || 
                   user.is_tutor || 
                   odRequest.student_id === req.user.id;
                   
    if (!canView) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    // Check if certificate exists
    if (!odRequest.certificate_url) {
      return res.status(404).json({ error: 'No certificate uploaded for this request' });
    }
    
    // Extract the path from the certificate URL stored in database
    const relativePath = odRequest.certificate_url.replace('/uploads/', '');
    const filePath = path.join(__dirname, 'uploads', relativePath);
    
    console.log(`Looking for certificate at: ${filePath}`);
    console.log(`Request ID: ${requestId}, Student ID: ${odRequest.student_id}`);
    console.log(`Certificate URL from DB: ${odRequest.certificate_url}`);
    console.log(`File exists: ${fs.existsSync(filePath)}`);
    
    // Check if file exists
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'Certificate file not found' });
    }
    
    // Get file extension to determine content type
    const ext = path.extname(filePath).toLowerCase();
    let contentType = 'application/octet-stream';
    
    switch (ext) {
      case '.pdf':
        contentType = 'application/pdf';
        break;
      case '.jpg':
      case '.jpeg':
        contentType = 'image/jpeg';
        break;
      case '.png':
        contentType = 'image/png';
        break;
      case '.gif':
        contentType = 'image/gif';
        break;
      case '.webp':
        contentType = 'image/webp';
        break;
    }
    
    // Set headers for inline viewing (preview)
    res.setHeader('Content-Type', contentType);
    res.setHeader('Content-Disposition', 'inline');
    res.setHeader('Cache-Control', 'public, max-age=86400'); // Cache for 1 day
    res.setHeader('X-Content-Type-Options', 'nosniff');
    
    // Send the file
    res.sendFile(filePath);
  } catch (error) {
    console.error('Certificate preview error:', error);
    res.status(500).json({ error: 'Failed to preview certificate' });
  }
});

// Certificate download endpoint (for downloading)
app.get('/api/certificate/:requestId/download', authenticateToken, async (req, res) => {
  try {
    const { requestId } = req.params;
    
    // Verify the OD request exists and the user has permission to view it
    const [odRequest] = await query('SELECT * FROM od_requests WHERE id = ?', [requestId]);
    if (!odRequest) {
      return res.status(404).json({ error: 'OD request not found' });
    }
    
    // Get user info to check permissions
    const [user] = await query('SELECT is_admin, is_tutor FROM users WHERE id = ?', [req.user.id]);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Check if user has permission to view this certificate
    const canView = user.is_admin || 
                   user.is_tutor || 
                   odRequest.student_id === req.user.id;
                   
    if (!canView) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    // Check if certificate exists
    if (!odRequest.certificate_url) {
      return res.status(404).json({ error: 'No certificate uploaded for this request' });
    }
    
    // Get student info for filename
    const [student] = await query('SELECT batch, register_number, name FROM students WHERE id = ?', [odRequest.student_id]);
    
    // Extract the path from the certificate URL stored in database
    const relativePath = odRequest.certificate_url.replace('/uploads/', '');
    const filePath = path.join(__dirname, 'uploads', relativePath);
    
    console.log(`Downloading certificate from: ${filePath}`);
    
    // Check if file exists
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'Certificate file not found' });
    }
    
    // Get file extension and original filename
    const ext = path.extname(filePath);
    const downloadFilename = `${student.name.replace(/\s+/g, '_')}_${student.register_number}_OD_Certificate${ext}`;
    
    // Set headers for download
    res.setHeader('Content-Disposition', `attachment; filename="${downloadFilename}"`);
    res.setHeader('Content-Type', 'application/octet-stream');
    
    // Send the file
    res.sendFile(filePath);
  } catch (error) {
    console.error('Certificate download error:', error);
    res.status(500).json({ error: 'Failed to download certificate' });
  }
});

// Legacy certificate viewing endpoint (deprecated - kept for backward compatibility)
app.get('/api/certificate/:requestId/:filename', authenticateToken, async (req, res) => {
  try {
    const { requestId, filename } = req.params;
    
    // Verify the OD request exists and the user has permission to view it
    const [odRequest] = await query('SELECT * FROM od_requests WHERE id = ?', [requestId]);
    if (!odRequest) {
      return res.status(404).json({ error: 'OD request not found' });
    }
    
    // Get user info to check permissions
    const [user] = await query('SELECT is_admin, is_tutor FROM users WHERE id = ?', [req.user.id]);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Check if user has permission to view this certificate
    const canView = user.is_admin || 
                   user.is_tutor || 
                   odRequest.student_id === req.user.id;
                   
    if (!canView) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    // Construct file path using the certificate URL from database
    const [student] = await query('SELECT batch, register_number FROM students WHERE id = ?', [odRequest.student_id]);
    
    // Extract the path from the certificate URL stored in database
    let filePath;
    if (odRequest.certificate_url) {
      // Remove the leading '/uploads' from the URL to get the relative path
      const relativePath = odRequest.certificate_url.replace('/uploads/', '');
      filePath = path.join(__dirname, 'uploads', relativePath);
    } else {
      // Fallback to new structure if no certificate_url
      filePath = path.join(__dirname, 'uploads', student.batch, student.register_number.toString(), 'certificate', filename);
    }
    
    console.log(`Looking for certificate at: ${filePath}`);
    console.log(`Request ID: ${requestId}, Student ID: ${odRequest.student_id}, Filename: ${filename}`);
    console.log(`Certificate URL from DB: ${odRequest.certificate_url}`);
    console.log(`File exists: ${fs.existsSync(filePath)}`);
    
    // Check if file exists
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'Certificate file not found' });
    }
    
    // Set appropriate headers based on file type
    const ext = path.extname(filename).toLowerCase();
    let contentType = 'application/octet-stream';
    
    switch (ext) {
      case '.pdf':
        contentType = 'application/pdf';
        break;
      case '.jpg':
      case '.jpeg':
        contentType = 'image/jpeg';
        break;
      case '.png':
        contentType = 'image/png';
        break;
      case '.gif':
        contentType = 'image/gif';
        break;
    }
    
    res.setHeader('Content-Type', contentType);
    res.setHeader('Content-Disposition', `inline; filename="${filename}"`);
    
    // Send the file
    res.sendFile(filePath);
  } catch (error) {
    console.error('Certificate viewing error:', error);
    res.status(500).json({ error: 'Failed to retrieve certificate' });
  }
});

// Enhanced Report Generation Endpoints
// =================================

// Generate comprehensive report data
app.get('/api/reports/data', express.json(), authenticateToken, async (req, res) => {
  try {
    const { 
      batch = 'all', 
      semester = 'all', 
      startDate, 
      endDate, 
      format = 'json',
      type = 'daily'
    } = req.query;

    // Check user permissions
    const [user] = await query('SELECT is_admin, is_tutor, id FROM users WHERE id = ?', [req.user.id]);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    let reportData = [];
    let metadata = {
      generatedAt: new Date().toISOString(),
      generatedBy: req.user.id,
      filters: { batch, semester, startDate, endDate, type },
      totalRecords: 0
    };

    if (type === 'daily' || type === 'summary') {
      // Get students based on filters
      let studentsQuery = `
        SELECT s.*, u.name as student_name, u.email, u.phone
        FROM students s 
        JOIN users u ON s.id = u.id
        WHERE 1=1
      `;
      let studentsParams = [];

      // Filter by tutor if not admin
      if (!user.is_admin && user.is_tutor) {
        studentsQuery += ' AND s.tutor_id = ?';
        studentsParams.push(req.user.id);
      }

      // Filter by batch if specified
      if (batch !== 'all') {
        studentsQuery += ' AND s.batch = ?';
        studentsParams.push(batch);
      }

      const students = await query(studentsQuery, studentsParams);
      const studentIds = students.map(s => s.id);

      if (type === 'daily' && startDate && endDate) {
        // Generate daily report data
        const start = new Date(startDate);
        const end = new Date(endDate);
        const daysDiff = Math.ceil((end - start) / (1000 * 60 * 60 * 24)) + 1;
        
        reportData = [];
        for (let i = 0; i < daysDiff; i++) {
          const currentDate = new Date(start);
          currentDate.setDate(start.getDate() + i);
          const dateStr = currentDate.toISOString().split('T')[0];
          
          // Get leave requests for this date
          const leaveQuery = `
            SELECT COUNT(DISTINCT lr.student_id) as count
            FROM leave_requests lr
            WHERE lr.status = 'Approved'
            AND lr.start_date <= ? AND lr.end_date >= ?
            ${studentIds.length > 0 ? `AND lr.student_id IN (${studentIds.map(() => '?').join(',')})` : ''}
          `;
          const leaveParams = [dateStr, dateStr, ...studentIds];
          const [leaveResult] = await query(leaveQuery, leaveParams);

          // Get OD requests for this date
          const odQuery = `
            SELECT COUNT(DISTINCT odr.student_id) as count
            FROM od_requests odr
            WHERE odr.status = 'Approved'
            AND odr.start_date <= ? AND odr.end_date >= ?
            ${studentIds.length > 0 ? `AND odr.student_id IN (${studentIds.map(() => '?').join(',')})` : ''}
          `;
          const odParams = [dateStr, dateStr, ...studentIds];
          const [odResult] = await query(odQuery, odParams);

          reportData.push({
            date: dateStr,
            studentsOnLeave: leaveResult.count || 0,
            studentsOnOD: odResult.count || 0,
            totalAbsent: (leaveResult.count || 0) + (odResult.count || 0)
          });
        }
      } else {
        // Generate detailed summary report data with actual leave and OD counts
        const tutorsQuery = 'SELECT id, name FROM users WHERE is_tutor = 1';
        const tutors = await query(tutorsQuery);
        const tutorsMap = new Map(tutors.map(t => [t.id, t.name]));

        // Calculate detailed data for each student
        const detailedReportData = await Promise.all(students.map(async (student) => {
          // Calculate total approved leave days for this student
          const leaveCountQuery = `
            SELECT 
              COUNT(*) as total_leave_requests,
              COALESCE(SUM(
                CASE 
                  WHEN duration_type IN ('half_day_forenoon', 'half_day_afternoon') 
                  THEN DATEDIFF(end_date, start_date) + 1 * 0.5
                  ELSE total_days
                END
              ), 0) as total_leave_days
            FROM leave_requests
            WHERE student_id = ? AND status = 'Approved'
          `;
          const [leaveResult] = await query(leaveCountQuery, [student.id]);

          // Calculate total approved OD days for this student
          const odCountQuery = `
            SELECT 
              COUNT(*) as total_od_requests,
              COALESCE(SUM(
                CASE 
                  WHEN duration_type IN ('half_day_forenoon', 'half_day_afternoon') 
                  THEN DATEDIFF(end_date, start_date) + 1 * 0.5
                  ELSE total_days
                END
              ), 0) as total_od_days
            FROM od_requests
            WHERE student_id = ? AND status = 'Approved'
          `;
          const [odResult] = await query(odCountQuery, [student.id]);

          return {
            'Name': student.student_name || student.name,
            'Register Number': student.register_number,
            'Batch': `${student.batch}-${parseInt(student.batch) + 4}`,
            'Semester': student.semester,
            'Total Leave Count': parseFloat(leaveResult.total_leave_days || 0).toFixed(1),
            'Total OD Count': parseFloat(odResult.total_od_days || 0).toFixed(1),
            'Tutor': tutorsMap.get(student.tutor_id) || 'N/A',
            'Email': student.email || 'N/A',
            'Phone': student.phone || 'N/A'
          };
        }));

        reportData = detailedReportData;
      }
    }

    metadata.totalRecords = reportData.length;

    // Return data based on format
    if (format === 'csv') {
      // Convert to CSV format
      const Papa = await import('papaparse');
      const csv = Papa.unparse(reportData);
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename="report-${Date.now()}.csv"`);
      return res.send(csv);
    }

    res.json({
      success: true,
      metadata,
      data: reportData
    });

  } catch (error) {
    console.error('Report generation error:', error);
    res.status(500).json({ error: 'Failed to generate report data' });
  }
});

// Get report statistics
app.get('/api/reports/stats', express.json(), authenticateToken, async (req, res) => {
  try {
    const { batch = 'all', semester = 'all' } = req.query;

    // Check user permissions
    const [user] = await query('SELECT is_admin, is_tutor FROM users WHERE id = ?', [req.user.id]);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    let whereClause = '1=1';
    let params = [];

    // Filter by tutor if not admin
    if (!user.is_admin && user.is_tutor) {
      whereClause += ' AND s.tutor_id = ?';
      params.push(req.user.id);
    }

    // Filter by batch
    if (batch !== 'all') {
      whereClause += ' AND s.batch = ?';
      params.push(batch);
    }

    // Get basic statistics
    const totalStudentsQuery = `SELECT COUNT(*) as count FROM students s WHERE ${whereClause}`;
    const [totalStudentsResult] = await query(totalStudentsQuery, params);

    const totalLeavesQuery = `
      SELECT COUNT(*) as count FROM leave_requests lr 
      JOIN students s ON lr.student_id = s.id 
      WHERE lr.status = 'Approved' AND ${whereClause}
    `;
    const [totalLeavesResult] = await query(totalLeavesQuery, params);

    const totalODsQuery = `
      SELECT COUNT(*) as count FROM od_requests odr 
      JOIN students s ON odr.student_id = s.id 
      WHERE odr.status = 'Approved' AND ${whereClause}
    `;
    const [totalODsResult] = await query(totalODsQuery, params);

    // Get current month statistics
    const currentMonth = new Date().toISOString().slice(0, 7); // YYYY-MM format
    const monthlyLeavesQuery = `
      SELECT COUNT(*) as count FROM leave_requests lr 
      JOIN students s ON lr.student_id = s.id 
      WHERE lr.status = 'Approved' 
      AND lr.start_date LIKE ?
      AND ${whereClause}
    `;
    const [monthlyLeavesResult] = await query(monthlyLeavesQuery, [`${currentMonth}%`, ...params]);

    res.json({
      success: true,
      data: {
        totalStudents: totalStudentsResult.count,
        totalLeaves: totalLeavesResult.count,
        totalODs: totalODsResult.count,
        monthlyLeaves: monthlyLeavesResult.count,
        averageLeavesPerStudent: totalStudentsResult.count > 0 
          ? (totalLeavesResult.count / totalStudentsResult.count).toFixed(2) 
          : '0.00'
      }
    });

  } catch (error) {
    console.error('Stats generation error:', error);
    res.status(500).json({ error: 'Failed to generate statistics' });
  }
});

// Backend HTTP port - default 3009, can be overridden by PORT env
const port = process.env.PORT || 3009;
const host = '0.0.0.0'; // Bind to all network interfaces for production access

// Create a connection pool
const pool = mysql.createPool(dbConfig);

// Utility function to execute queries
async function query(sql, params) {
  const [results] = await pool.execute(sql, params);
  return results;
}

// Session management functions
async function createSession(userId, token) {
  const sessionId = uuidv4();
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours from now
  
  await query(
    'INSERT INTO user_sessions (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?)',
    [sessionId, userId, tokenHash, expiresAt]
  );
  
  return sessionId;
}

async function invalidateUserSessions(userId) {
  await query(
    'UPDATE user_sessions SET is_active = 0 WHERE user_id = ? AND is_active = 1',
    [userId]
  );
}

async function isSessionValid(token) {
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const [session] = await query(
    'SELECT * FROM user_sessions WHERE token_hash = ? AND is_active = 1 AND expires_at > NOW()',
    [tokenHash]
  );
  return !!session;
}

async function cleanupExpiredSessions() {
  await query('UPDATE user_sessions SET is_active = 0 WHERE expires_at <= NOW()');
}

// Add express.json() middleware for non-file-upload routes
// This must come after the file upload routes to avoid interfering with multipart form data
app.use('/api/od-requests/:id/certificate', (req, res, next) => {
  // Skip express.json for file upload endpoints
  if (req.method === 'POST') {
    return next();
  }
  express.json()(req, res, next);
});

// Apply express.json to all other routes
app.use(express.json());

// Root endpoint
app.get('/', (req, res) => {
  res.json({ 
    message: 'MySQL Backend API Server is running!', 
    status: 'OK',
    port: port,
    endpoints: {
      testDb: '/test-db',
      login: '/auth/login',
      profile: '/profile',
      students: '/students',
      staff: '/staff',
      leaveRequests: '/leave-requests',
      odRequests: '/od-requests'
    }
  });
});

// Add user registration
app.post('/register', async (req, res) => {
  try {
    const { email, password, firstName, lastName } = req.body;
    const id = uuidv4();
    const passwordHash = await bcrypt.hash(password, 10);

    const userInsert = await query('INSERT INTO users (id, email, password_hash, first_name, last_name) VALUES (?, ?, ?, ?, ?)', [id, email, passwordHash, firstName, lastName]);
    res.status(201).json({ message: 'User registered successfully!', userId: id });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to register user.' });
  }
});

// Add user login
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const [user] = await query('SELECT * FROM users WHERE email = ?', [email]);
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = jwt.sign({ id: user.id }, jwtSecret, { expiresIn: '1h' });
    res.json({ message: 'Logged in successfully', token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to login user.' });
  }
});

// JWT middleware for authentication with session validation
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.sendStatus(401);
  }

  jwt.verify(token, jwtSecret, async (err, user) => {
    if (err) return res.sendStatus(403);
    
    // Check if the session is still valid
    const sessionValid = await isSessionValid(token);
    if (!sessionValid) {
      return res.status(401).json({ 
        error: 'Session expired or invalid. Please login again.',
        code: 'SESSION_INVALID'
      });
    }
    
    // Fetch user roles for RBAC
    try {
      const [dbUser] = await query('SELECT id, is_admin, is_tutor FROM users WHERE id = ?', [user.id]);
      if (!dbUser) {
        return res.sendStatus(403);
      }
      req.user = { ...user, ...dbUser };
    } catch (dbError) {
      console.error('RBAC Error:', dbError);
      return res.sendStatus(500);
    }

    req.token = token;
    next();
  });
}

// Get user profile
app.get('/profile', authenticateToken, async (req, res) => {
  try {
    const [user] = await query(
      'SELECT id, email, first_name, last_name, profile_photo, is_admin, is_tutor FROM users WHERE id = ?',
      [req.user.id]
    );
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Add the best profile picture URL (custom or Gravatar)
    user.profile_photo = getBestProfilePicture(user.profile_photo, user.email);
    
    res.json(user);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// Get all students
app.get('/students', authenticateToken, async (req, res) => {
  try {
    let queryStr = 'SELECT * FROM students';
    let params = [];

    // RBAC: Filter students based on user role
    if (req.user.is_admin) {
      queryStr += ' ORDER BY name';
    } else if (req.user.is_tutor) {
      queryStr += ' WHERE tutor_id = ? ORDER BY name';
      params.push(req.user.id);
    } else {
      queryStr += ' WHERE id = ?';
      params.push(req.user.id);
    }

    const students = await query(queryStr, params);
    
    // Add Gravatar profile pictures and calculate dynamic leave_taken for students
    const studentsWithUpdatedData = await Promise.all(students.map(async (student) => {
      const dynamicLeaveTaken = await calculateLeaveTaken(student.id);
      return {
        ...student,
        leave_taken: dynamicLeaveTaken, // Override with dynamic calculation
        profile_photo: getBestProfilePicture(student.profile_photo, student.email)
      };
    }));
    
    res.json(studentsWithUpdatedData);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch students' });
  }
});

// Get specific student by ID
app.get('/students/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const [student] = await query('SELECT * FROM students WHERE id = ?', [id]);
    
    if (!student) {
      return res.status(404).json({ error: 'Student not found' });
    }
    
    // Calculate dynamic leave_taken and add profile picture
    const dynamicLeaveTaken = await calculateLeaveTaken(student.id);
    const studentWithUpdatedData = {
      ...student,
      leave_taken: dynamicLeaveTaken, // Override with dynamic calculation
      profile_photo: getBestProfilePicture(student.profile_photo, student.email)
    };
    
    res.json(studentWithUpdatedData);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch student' });
  }
});

// Get all staff
app.get('/staff', authenticateToken, async (req, res) => {
  try {
    const staff = await query('SELECT * FROM staff ORDER BY name');
    
    // Add Gravatar profile pictures for staff without custom photos
    const staffWithProfilePictures = staff.map(staffMember => ({
      ...staffMember,
      profile_photo: getBestProfilePicture(staffMember.profile_photo, staffMember.email)
    }));
    
    res.json(staffWithProfilePictures);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch staff' });
  }
});

// Upload profile photo
app.post('/upload/profile-photo', authenticateToken, profileUpload.single('profilePhoto'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const userId = req.user.id;
    
    // First, check what type of user this is
    const [user] = await query('SELECT is_admin, is_tutor FROM users WHERE id = ?', [userId]);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    let userProfileDir;
    let profilePhotoUrl;
    
    if (user.is_admin || user.is_tutor) {
      // For staff members (tutors/admins)
      const [staff] = await query('SELECT name FROM staff WHERE id = ?', [userId]);
      if (!staff) {
        return res.status(404).json({ error: 'Staff record not found' });
      }
      
      if (user.is_admin) {
        // For admins, use simple structure: uploads/Admin/profile.png
        userProfileDir = path.join(__dirname, 'uploads', 'Admin');
        profilePhotoUrl = `/uploads/Admin/profile.png`;
      } else {
        // For tutors, use simplified structure: uploads/{tutor_name}/profile.png
        const sanitizedName = staff.name.replace(/[^a-zA-Z0-9\s-]/g, '').replace(/\s+/g, '-').toLowerCase();
        userProfileDir = path.join(__dirname, 'uploads', sanitizedName);
        profilePhotoUrl = `/uploads/${sanitizedName}/profile.png`;
      }
    } else {
      // For students, use batch/rollnumber structure
      const [student] = await query('SELECT batch, register_number FROM students WHERE id = ?', [userId]);
      if (!student) {
        return res.status(404).json({ error: 'Student record not found' });
      }
      
      // Create directory structure: uploads/{batch}/{rollnumber}/profile/
      userProfileDir = path.join(__dirname, 'uploads', student.batch, student.register_number.toString(), 'profile');
      profilePhotoUrl = `/uploads/${student.batch}/${student.register_number}/profile/profile.png`;
    }
    
    // Create the directory if it doesn't exist
    if (!fs.existsSync(userProfileDir)) {
      fs.mkdirSync(userProfileDir, { recursive: true });
    }

    // Check if old profile photo exists and delete it
    const finalFilePath = path.join(userProfileDir, 'profile.png');
    if (fs.existsSync(finalFilePath)) {
      try {
        fs.unlinkSync(finalFilePath);
        console.log(`Deleted old profile photo: ${finalFilePath}`);
      } catch (deleteError) {
        console.warn('Failed to delete old profile photo:', deleteError);
      }
    }

    // Process and save the new image as profile.png
    const tempFilePath = req.file.path;
    await sharp(tempFilePath)
      .png({ quality: 90 }) // Convert to PNG format
      .toFile(finalFilePath);
    
    // Remove the temporary file
    fs.unlinkSync(tempFilePath);

    // Update the user's profile photo in the database
    try {
      // Update the users table with the new profile photo
      await query('UPDATE users SET profile_photo = ? WHERE id = ?', [profilePhotoUrl, userId]);

      // Also update the appropriate table (students or staff)
      if (user.is_admin || user.is_tutor) {
        // Update staff table
        await query('UPDATE staff SET profile_photo = ? WHERE id = ?', [profilePhotoUrl, userId]);
      } else {
        // Update students table
        await query('UPDATE students SET profile_photo = ? WHERE id = ?', [profilePhotoUrl, userId]);
      }

      console.log(`Profile photo updated for user ${userId}: ${profilePhotoUrl}`);

    } catch (dbError) {
      console.error('Database update error:', dbError);
      // If database update fails, we should delete the uploaded file
      try {
        fs.unlinkSync(finalFilePath);
      } catch (deleteError) {
        console.error('Failed to delete uploaded file after database error:', deleteError);
      }
      return res.status(500).json({ error: 'Failed to update profile photo in database' });
    }

    res.json({ 
      message: 'Profile photo uploaded and updated successfully', 
      filePath: profilePhotoUrl 
    });

  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: 'Failed to upload photo' });
  }
});

// Remove profile photo
app.delete('/upload/profile-photo', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    
    // Get current profile photo path and user type
    const [user] = await query('SELECT profile_photo, is_admin, is_tutor FROM users WHERE id = ?', [userId]);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const currentPhotoPath = user.profile_photo;
    
    // Update database to remove profile photo
    try {
      // Update the users table to remove profile photo
      await query('UPDATE users SET profile_photo = NULL WHERE id = ?', [userId]);
      
      // Also update the appropriate table (students or staff)
      if (user.is_admin || user.is_tutor) {
        // Update staff table
        await query('UPDATE staff SET profile_photo = NULL WHERE id = ?', [userId]);
      } else {
        // Update students table
        await query('UPDATE students SET profile_photo = NULL WHERE id = ?', [userId]);
      }
      
      console.log(`Profile photo removed for user ${userId}`);
      
    } catch (dbError) {
      console.error('Database update error:', dbError);
      return res.status(500).json({ error: 'Failed to remove profile photo from database' });
    }
    
    // Delete the physical file if it exists
    if (currentPhotoPath && currentPhotoPath.startsWith('/uploads/')) {
      try {
        // Construct the full file path from the URL
        const relativePath = currentPhotoPath.replace('/uploads/', '');
        const fullPath = path.join(__dirname, 'uploads', relativePath);
        
        if (fs.existsSync(fullPath)) {
          fs.unlinkSync(fullPath);
          console.log(`Deleted profile photo file: ${fullPath}`);
          
          // Try to remove the parent directory if it's empty (but not for admin)
          if (!currentPhotoPath.includes('/Admin/')) {
            try {
              const parentDir = path.dirname(fullPath);
              const files = fs.readdirSync(parentDir);
              if (files.length === 0) {
                fs.rmdirSync(parentDir);
                console.log(`Removed empty directory: ${parentDir}`);
                
                // Try to remove the student's main directory if it's empty too
                const studentDir = path.dirname(parentDir);
                const studentFiles = fs.readdirSync(studentDir);
                if (studentFiles.length === 0) {
                  fs.rmdirSync(studentDir);
                  console.log(`Removed empty student directory: ${studentDir}`);
                }
              }
            } catch (dirError) {
              console.warn('Could not remove empty directories:', dirError);
            }
          }
        }
      } catch (fileError) {
        console.warn('Failed to delete profile photo file:', fileError);
        // Don't fail the request if file deletion fails
      }
    }
    
    res.json({ 
      message: 'Profile photo removed successfully'
    });
    
  } catch (error) {
    console.error('Remove profile photo error:', error);
    res.status(500).json({ error: 'Failed to remove profile photo' });
  }
});

// Create a new student
app.post('/students', authenticateToken, async (req, res) => {
  try {
    const { email, password, name, registerNumber, tutorId, batch, semester, mobile } = req.body;
    const id = uuidv4();
    const passwordHash = await bcrypt.hash(password, 10);

    // Insert into users table first
    await query(
      'INSERT INTO users (id, email, password_hash, first_name, last_name) VALUES (?, ?, ?, ?, ?)',
      [id, email, passwordHash, name.split(' ')[0], name.split(' ').slice(1).join(' ')]
    );

    // Insert into students table
    const username = email.split('@')[0]; // Generate username from email
    try {
      await query(
        'INSERT INTO students (id, name, register_number, tutor_id, batch, semester, email, mobile, username) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [id, name, registerNumber, tutorId, batch, semester, email, mobile, username]
      );
    } catch (error) {
      // If username column doesn't exist, try without it
      if (error.message.includes('Unknown column') && error.message.includes('username')) {
        await query(
          'INSERT INTO students (id, name, register_number, tutor_id, batch, semester, email, mobile) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
          [id, name, registerNumber, tutorId, batch, semester, email, mobile]
        );
      } else {
        throw error;
      }
    }

    res.status(201).json({ message: 'Student created successfully', id });
  } catch (error) {
    console.error('Error creating student:', error);
    res.status(500).json({ error: 'Failed to create student', details: error.message });
  }
});

// Create a new staff member
app.post('/staff', authenticateToken, async (req, res) => {
  try {
    const { email, password, name, username, isAdmin, isTutor } = req.body;
    const id = uuidv4();
    const passwordHash = await bcrypt.hash(password, 10);

    // Insert into users table first
    await query(
      'INSERT INTO users (id, email, password_hash, first_name, last_name, is_admin, is_tutor) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [id, email, passwordHash, name.split(' ')[0], name.split(' ').slice(1).join(' '), isAdmin, isTutor]
    );

    // Insert into staff table
    await query(
      'INSERT INTO staff (id, name, email, username, is_admin, is_tutor) VALUES (?, ?, ?, ?, ?, ?)',
      [id, name, email, username, isAdmin, isTutor]
    );

    res.status(201).json({ message: 'Staff member created successfully', id });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to create staff member' });
  }
});

// Update student
app.put('/students/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { password, ...studentUpdates } = req.body;
    
    // Update students table (excluding password as it's not stored there)
    if (Object.keys(studentUpdates).length > 0) {
      const setClause = Object.keys(studentUpdates).map(key => `${key} = ?`).join(', ');
      const values = Object.values(studentUpdates);
      values.push(id);
      await query(`UPDATE students SET ${setClause} WHERE id = ?`, values);
    }
    
    // Update password in users table if provided
    if (password) {
      const passwordHash = await bcrypt.hash(password, 10);
      await query('UPDATE users SET password_hash = ? WHERE id = ?', [passwordHash, id]);
      console.log(`Password updated for student ${id}`);
    }
    
    const [updatedStudent] = await query('SELECT * FROM students WHERE id = ?', [id]);
    res.json(updatedStudent);
  } catch (error) {
    console.error('Error updating student:', error);
    res.status(500).json({ error: 'Failed to update student' });
  }
});

// Update staff
app.put('/staff/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { password, ...staffUpdates } = req.body;
    
    // Update staff table (excluding password as it's not stored there)
    if (Object.keys(staffUpdates).length > 0) {
      const setClause = Object.keys(staffUpdates).map(key => `${key} = ?`).join(', ');
      const values = Object.values(staffUpdates);
      values.push(id);
      await query(`UPDATE staff SET ${setClause} WHERE id = ?`, values);
    }
    
    // Update password in users table if provided
    if (password) {
      const passwordHash = await bcrypt.hash(password, 10);
      await query('UPDATE users SET password_hash = ? WHERE id = ?', [passwordHash, id]);
      console.log(`Password updated for staff member ${id}`);
    }
    
    const [updatedStaff] = await query('SELECT * FROM staff WHERE id = ?', [id]);
    res.json(updatedStaff);
  } catch (error) {
    console.error('Error updating staff:', error);
    res.status(500).json({ error: 'Failed to update staff' });
  }
});

// Create a new batch
app.post('/batches', authenticateToken, async (req, res) => {
  try {
    const { startYear } = req.body;
    const id = startYear.toString();
    const endYear = startYear + 4;
    const name = `${startYear}-${endYear}`;

    // Check if batch already exists
    const [existingBatch] = await query('SELECT id FROM batches WHERE id = ?', [id]);
    if (existingBatch) {
      return res.status(409).json({ error: 'A batch with this start year already exists' });
    }

    await query(
      'INSERT INTO batches (id, start_year, end_year, name, is_active) VALUES (?, ?, ?, ?, ?)',
      [id, startYear, endYear, name, true]
    );

    res.status(201).json({ message: 'Batch created successfully', id });
  } catch (error) {
    console.error(error);
    if (error.code === 'ER_DUP_ENTRY') {
      res.status(409).json({ error: 'A batch with this start year already exists' });
    } else {
      res.status(500).json({ error: 'Failed to create batch', details: error.message });
    }
  }
});

// Update a batch
app.put('/batches/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const updates = req.body;
    
    const setClause = Object.keys(updates).map(key => `${key} = ?`).join(', ');
    const values = Object.values(updates);
    values.push(id);

    await query(`UPDATE batches SET ${setClause} WHERE id = ?`, values);
    
    const [updatedBatch] = await query('SELECT * FROM batches WHERE id = ?', [id]);
    res.json(updatedBatch);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to update batch', details: error.message });
  }
});

// Delete a batch
app.delete('/batches/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Check if there are students associated with this batch
    const [studentsInBatch] = await query('SELECT COUNT(*) as count FROM students WHERE batch = ?', [id]);
    
    if (studentsInBatch.count > 0) {
      return res.status(400).json({ 
        error: 'Cannot delete batch', 
        details: `This batch has ${studentsInBatch.count} students associated with it. Please reassign or remove students before deleting the batch.` 
      });
    }
    
    // Check if there are leave requests associated with this batch
    const [leaveRequestsInBatch] = await query(
      'SELECT COUNT(*) as count FROM leave_requests lr JOIN students s ON lr.student_id = s.id WHERE s.batch = ?', 
      [id]
    );
    
    if (leaveRequestsInBatch.count > 0) {
      return res.status(400).json({ 
        error: 'Cannot delete batch', 
        details: `This batch has ${leaveRequestsInBatch.count} leave requests associated with it. Please archive or handle these requests before deleting the batch.` 
      });
    }
    
    // Check if there are OD requests associated with this batch
    const [odRequestsInBatch] = await query(
      'SELECT COUNT(*) as count FROM od_requests or JOIN students s ON or.student_id = s.id WHERE s.batch = ?', 
      [id]
    );
    
    if (odRequestsInBatch.count > 0) {
      return res.status(400).json({ 
        error: 'Cannot delete batch', 
        details: `This batch has ${odRequestsInBatch.count} OD requests associated with it. Please archive or handle these requests before deleting the batch.` 
      });
    }
    
    // If no associated data, proceed with deletion
    const [result] = await query('DELETE FROM batches WHERE id = ?', [id]);
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Batch not found' });
    }
    
    res.json({ message: 'Batch deleted successfully' });
  } catch (error) {
    console.error('Error deleting batch:', error);
    
    // Handle specific MySQL errors
    if (error.code === 'ER_ROW_IS_REFERENCED_2') {
      res.status(400).json({ 
        error: 'Cannot delete batch', 
        details: 'This batch is referenced by other records in the system. Please remove all associated data first.' 
      });
    } else {
      res.status(500).json({ error: 'Failed to delete batch', details: error.message });
    }
  }
});

// Get all batches
app.get('/batches', authenticateToken, async (req, res) => {
  try {
    const batches = await query('SELECT * FROM batches ORDER BY start_year');
    res.json(batches);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to retrieve batches', details: error.message });
  }
});

// Update student profile (direct update)
app.put('/students/sync-batch-status/:batchId', authenticateToken, async (req, res) => {
  try {
    const { batchId } = req.params;
    const { isActive } = req.body;

    // Update all students in this batch to have the correct active status
    const [result] = await query(
      'UPDATE students SET is_active = ? WHERE batch = ?',
      [isActive, batchId]
    );

    if (result.affectedRows > 0) {
      res.json({ message: `${result.affectedRows} students updated`, updatedCount: result.affectedRows });
    } else {
      res.status(404).json({ error: 'No students found for this batch' });
    }
  } catch (error) {
    console.error('Failed to update students status:', error);
    res.status(500).json({ error: 'Failed to update students status' });
  }
});

// Update student semesters with batch (syncing current semester)
app.put('/students/sync-batch-semester/:batchId', authenticateToken, async (req, res) => {
  try {
    const { batchId } = req.params;
    const { semester } = req.body;

    if (!semester) {
      return res.status(400).json({ error: 'Semester number is required' });
    }

    // Update all students in this batch to the specified semester
    const [result] = await query(
      'UPDATE students SET semester = ? WHERE batch = ?',
      [semester, batchId]
    );

    res.json({ 
      message: `${result.affectedRows} students updated to semester ${semester}`, 
      updatedCount: result.affectedRows 
    });
  } catch (error) {
    console.error('Failed to update students semester:', error);
    res.status(500).json({ error: 'Failed to update students semester' });
  }
});

app.put('/students/:id/profile', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { email, mobile, password } = req.body;
    
    // Update students table
    const studentUpdates = {};
    if (email) studentUpdates.email = email;
    if (mobile) studentUpdates.mobile = mobile;
    
    if (Object.keys(studentUpdates).length > 0) {
      const setClause = Object.keys(studentUpdates).map(key => `${key} = ?`).join(', ');
      const values = Object.values(studentUpdates);
      values.push(id);
      await query(`UPDATE students SET ${setClause} WHERE id = ?`, values);
    }
    
    // Update users table for email and password changes
    if (email) {
      await query('UPDATE users SET email = ? WHERE id = ?', [email, id]);
    }
    
    // Update password if provided
    if (password) {
      const passwordHash = await bcrypt.hash(password, 10);
      await query('UPDATE users SET password_hash = ? WHERE id = ?', [passwordHash, id]);
    }
    
    // Send notifications to tutor and admin
    try {
      const [student] = await query('SELECT * FROM students WHERE id = ?', [id]);
      if (student) {
        const [tutor] = await query('SELECT * FROM staff WHERE id = ?', [student.tutor_id]);
        
        // Create notification message
        const changes = [];
        if (email) changes.push(`Email to ${email}`);
        if (mobile) changes.push(`Mobile to ${mobile}`);
        const notificationMessage = `Student ${student.name} updated their profile: ${changes.join(', ')}`;
        
        console.log('Profile update notification:', notificationMessage);
        // Here you could implement actual email/push notifications
      }
    } catch (notificationError) {
      console.warn('Failed to send notification:', notificationError);
    }
    
    const [updatedStudent] = await query('SELECT * FROM students WHERE id = ?', [id]);
    res.json(updatedStudent);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to update student profile' });
  }
});

// Update staff profile (direct update)
app.put('/staff/:id/profile', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { email, mobile, password } = req.body;
    
    // Update staff table
    const staffUpdates = {};
    if (email) staffUpdates.email = email;
    if (mobile) staffUpdates.mobile = mobile;
    
    if (Object.keys(staffUpdates).length > 0) {
      const setClause = Object.keys(staffUpdates).map(key => `${key} = ?`).join(', ');
      const values = Object.values(staffUpdates);
      values.push(id);
      await query(`UPDATE staff SET ${setClause} WHERE id = ?`, values);
    }
    
    // Update users table for email and password changes
    if (email) {
      await query('UPDATE users SET email = ? WHERE id = ?', [email, id]);
    }
    
    // Update password if provided
    if (password) {
      const passwordHash = await bcrypt.hash(password, 10);
      await query('UPDATE users SET password_hash = ? WHERE id = ?', [passwordHash, id]);
    }
    
    // Send notifications to admin (if user is tutor)
    try {
      const [staff] = await query('SELECT * FROM staff WHERE id = ?', [id]);
      if (staff && staff.is_tutor && !staff.is_admin) {
        // Create notification message for admin
        const changes = [];
        if (email) changes.push(`Email to ${email}`);
        if (mobile) changes.push(`Mobile to ${mobile}`);
        const notificationMessage = `Tutor ${staff.name} updated their profile: ${changes.join(', ')}`;
        
        console.log('Tutor profile update notification:', notificationMessage);
        // Here you could implement actual email/push notifications to admin
      }
    } catch (notificationError) {
      console.warn('Failed to send notification:', notificationError);
    }
    
    const [updatedStaff] = await query('SELECT * FROM staff WHERE id = ?', [id]);
    res.json(updatedStaff);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to update staff profile' });
  }
});

// Delete student - DISABLED FOR SECURITY
/* COMMENTED OUT TO PREVENT STUDENT DELETION
// app.delete('/students/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    await query('DELETE FROM students WHERE id = ?', [id]);
    await query('DELETE FROM users WHERE id = ?', [id]);
    res.json({ message: 'Student deleted successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to delete student' });
  }
});
*/

// Delete staff - DISABLED FOR SECURITY
/* COMMENTED OUT TO PREVENT STAFF DELETION
// app.delete('/staff/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    await query('DELETE FROM staff WHERE id = ?', [id]);
    await query('DELETE FROM users WHERE id = ?', [id]);
    res.json({ message: 'Staff deleted successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to delete staff' });
  }
});
*/

// Get leave requests
app.get('/leave-requests', authenticateToken, async (req, res) => {
  try {
    let queryStr = 'SELECT * FROM leave_requests';
    let params = [];

    // RBAC: Filter leave requests based on user role
    if (req.user.is_admin) {
      queryStr += ' ORDER BY created_at DESC';
    } else if (req.user.is_tutor) {
      queryStr += ' WHERE tutor_id = ? ORDER BY created_at DESC';
      params.push(req.user.id);
    } else {
      queryStr += ' WHERE student_id = ? ORDER BY created_at DESC';
      params.push(req.user.id);
    }

    const leaveRequests = await query(queryStr, params);
    res.json(leaveRequests);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch leave requests' });
  }
});

// Create leave request with date validation
app.post('/leave-requests', authenticateToken, async (req, res) => {
  try {
    const { startDate, endDate, totalDays, subject, description, duration_type } = req.body;
    const id = uuidv4();
    
    // Debug logging
    console.log('📝 Leave Request Data:', {
      startDate,
      endDate,
      totalDays,
      duration_type,
      subject: subject?.substring(0, 20) + '...'
    });

    // Validate exception days - Check if any date in the range is an exception day
    console.log('🚫 Checking exception days for date range:', { startDate, endDate });
    
    const exceptionDaysInRange = await query(
      `SELECT date, reason FROM exception_days 
       WHERE date BETWEEN ? AND ? 
       ORDER BY date`,
      [startDate, endDate]
    );
    
    if (exceptionDaysInRange.length > 0) {
      const conflictingDates = exceptionDaysInRange.map(day => {
        const dateStr = new Date(day.date).toISOString().split('T')[0];
        return `${dateStr} (${day.reason})`;
      });
      console.log('🚫 Exception days found in range:', conflictingDates);
      
      return res.status(400).json({ 
        error: `Cannot apply for leave on the following exception days: ${conflictingDates.join(', ')}. Please select different dates.`,
        conflictingDates: exceptionDaysInRange.map(day => new Date(day.date).toISOString().split('T')[0])
      });
    }
    
    console.log('✅ No exception days found in range, proceeding with leave request');

    // Check for overlapping leave or OD requests
    const overlapCheck = await query(
      `SELECT COUNT(*) as overlapCount
       FROM leave_requests
       WHERE student_id = ? AND status IN ('Approved', 'Pending')
       AND GREATEST(?, start_date) <= LEAST(?, end_date)`,
      [req.user.id, startDate, endDate]
    );

    const odOverlapCheck = await query(
      `SELECT COUNT(*) as overlapCount
       FROM od_requests
       WHERE student_id = ? AND status IN ('Approved', 'Pending')
       AND GREATEST(?, start_date) <= LEAST(?, end_date)`,
      [req.user.id, startDate, endDate]
    );

    if (overlapCheck[0].overlapCount > 0 || odOverlapCheck[0].overlapCount > 0) {
      return res.status(400).json({ error: 'Leave or OD request for these dates already exists.' });
    }

    // Get student and tutor info
    const [student] = await query('SELECT * FROM students WHERE id = ?', [req.user.id]);
    const [tutor] = await query('SELECT * FROM staff WHERE id = ?', [student.tutor_id]);

    await query(
      'INSERT INTO leave_requests (id, student_id, student_name, student_register_number, tutor_id, tutor_name, start_date, end_date, total_days, duration_type, subject, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [id, req.user.id, student.name, student.register_number, student.tutor_id, tutor.name, startDate, endDate, totalDays, duration_type || 'full_day', subject, description]
    );

    // Create notifications for tutor and admin
    try {
      // Notification for tutor
      await createNotification(
        student.tutor_id,
        'New Leave Request',
        `${student.name} has requested ${totalDays} day(s) for "${subject}".`,
        'leave_request',
        id,
        'leave_request',
        '/tutor-leave-approve'
      );

      // Notification for all admins
      const admins = await query('SELECT id FROM users WHERE is_admin = TRUE');
      for (const admin of admins) {
        await createNotification(
          admin.id,
          'New Leave Request',
          `${student.name} has submitted a leave request for "${subject}".`,
          'leave_request',
          id,
          'leave_request',
          '/admin-leave-requests'
        );
      }
    } catch (notificationError) {
      console.error('Error creating leave request notifications:', notificationError);
      // Don't fail the request creation if notifications fail
    }

    res.status(201).json({ message: 'Leave request created successfully', id });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to create leave request' });
  }
});

// Helper function to calculate days between dates
const calculateDaysBetween = (startDate, endDate) => {
  const start = new Date(startDate);
  const end = new Date(endDate);
  const timeDifference = end.getTime() - start.getTime();
  return Math.ceil(timeDifference / (1000 * 3600 * 24)) + 1;
};

// Update leave request status
app.put('/leave-requests/:id/status', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { status, cancelReason, startDate, endDate, isPartial } = req.body;
    
    // Get the original request to check current status and student info
    const [originalRequest] = await query('SELECT * FROM leave_requests WHERE id = ?', [id]);
    if (!originalRequest) {
      return res.status(404).json({ error: 'Leave request not found' });
    }
    
    // Get current student data
    const [student] = await query('SELECT * FROM students WHERE id = ?', [originalRequest.student_id]);
    if (!student) {
      return res.status(404).json({ error: 'Student not found' });
    }
    
    // Get current user info to check permissions
    const [userProfile] = await query('SELECT is_admin, is_tutor FROM users WHERE id = ?', [req.user.id]);
    if (!userProfile) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Enforce rejection reason for admin/tutor rejections
    if (status === 'Rejected' && (userProfile.is_admin || userProfile.is_tutor)) {
      if (!cancelReason || !cancelReason.trim()) {
        return res.status(400).json({ 
          error: 'Rejection reason is required when rejecting requests.' 
        });
      }
    }

    // Business rule: Tutors can only reject leave requests <= 2 days
    // For > 2 days, tutors can only forward (not reject)
    // Only admins can reject requests of any length
    if (userProfile.is_tutor && !userProfile.is_admin && status === 'Rejected') {
      if (originalRequest.total_days > 2) {
        return res.status(403).json({ 
          error: 'Tutors cannot reject leave requests longer than 2 days. You can only forward such requests to admin.' 
        });
      }
    }
    
    // Date validation: Prevent retry or cancellation if end date has passed
    const requestEndDate = new Date(originalRequest.end_date);
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    requestEndDate.setHours(0, 0, 0, 0);
    const dateHasPassed = today > requestEndDate;
    
    if (dateHasPassed) {
      if (status === 'Retried' && originalRequest.status === 'Rejected') {
        return res.status(400).json({ 
          error: 'Cannot retry this request because the leave end date has already passed.' 
        });
      }
      if (status === 'Cancellation Pending' && 
          (originalRequest.status === 'Pending' || originalRequest.status === 'Approved' || originalRequest.status === 'Forwarded')) {
        return res.status(400).json({ 
          error: 'Cannot request cancellation because the leave end date has already passed.' 
        });
      }
    }
    
    let updateData = {
      status: status,
      cancel_reason: cancelReason || null
    };
    
    let newLeaveTaken = student.leave_taken;
    
    // Handle partial cancellation for approved leave requests
    if (isPartial && originalRequest.status === 'Approved' && status === 'Cancellation Pending') {
      const partialDays = calculateDaysBetween(startDate, endDate);
      
      // Store partial cancellation data
      updateData.partial_cancel_start = startDate;
      updateData.partial_cancel_end = endDate;
      updateData.partial_cancel_days = partialDays;
      
      // Subtract the partially cancelled days from leave taken
      newLeaveTaken = Math.max(0, student.leave_taken - partialDays);
      
      // Update the total days of the request to reflect partial cancellation
      updateData.total_days = originalRequest.total_days - partialDays;
    }
    
    // NOTE: We no longer update the static leave_taken field in students table
    // since we now calculate it dynamically from approved leave requests
    
    // Update the leave request
    const setClause = Object.keys(updateData).map(key => `${key} = ?`).join(', ');
    const values = Object.values(updateData);
    values.push(id);
    
    await query(`UPDATE leave_requests SET ${setClause} WHERE id = ?`, values);
    
    const [updatedRequest] = await query('SELECT * FROM leave_requests WHERE id = ?', [id]);
    res.json(updatedRequest);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to update leave request status' });
  }
});

// Get OD requests
app.get('/od-requests', authenticateToken, async (req, res) => {
  try {
    let queryStr = 'SELECT * FROM od_requests';
    let params = [];

    // RBAC: Filter OD requests based on user role
    if (req.user.is_admin) {
      queryStr += ' ORDER BY created_at DESC';
    } else if (req.user.is_tutor) {
      queryStr += ' WHERE tutor_id = ? ORDER BY created_at DESC';
      params.push(req.user.id);
    } else {
      queryStr += ' WHERE student_id = ? ORDER BY created_at DESC';
      params.push(req.user.id);
    }

    const odRequests = await query(queryStr, params);
    res.json(odRequests);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch OD requests' });
  }
});

// Create OD request with date validation and photo upload
app.post('/od-requests', authenticateToken, odPhotoUpload.single('photo'), async (req, res) => {
  try {
    const { startDate, endDate, totalDays, purpose, destination, description, duration_type } = req.body;
    const id = uuidv4();
    
    // Debug logging
    console.log('🏢 OD Request Data:', {
      startDate,
      endDate,
      totalDays,
      duration_type,
      purpose: purpose?.substring(0, 20) + '...'
    });

    // Validate exception days - Check if any date in the range is an exception day
    console.log('🚫 Checking exception days for OD request date range:', { startDate, endDate });
    
    const exceptionDaysInRange = await query(
      `SELECT date, reason FROM exception_days 
       WHERE date BETWEEN ? AND ? 
       ORDER BY date`,
      [startDate, endDate]
    );
    
    if (exceptionDaysInRange.length > 0) {
      const conflictingDates = exceptionDaysInRange.map(day => {
        const dateStr = new Date(day.date).toISOString().split('T')[0];
        return `${dateStr} (${day.reason})`;
      });
      console.log('🚫 Exception days found in OD request range:', conflictingDates);
      
      return res.status(400).json({ 
        error: `Cannot apply for OD on the following exception days: ${conflictingDates.join(', ')}. Please select different dates.`,
        conflictingDates: exceptionDaysInRange.map(day => new Date(day.date).toISOString().split('T')[0])
      });
    }
    
    console.log('✅ No exception days found in OD request range, proceeding');

    // Check for overlapping leave or OD requests
    const leaveOverlapCheck = await query(
      `SELECT COUNT(*) as overlapCount
       FROM leave_requests
       WHERE student_id = ? AND status IN ('Approved', 'Pending')
       AND GREATEST(?, start_date) <= LEAST(?, end_date)`,
      [req.user.id, startDate, endDate]
    );

    const odOverlapCheck = await query(
      `SELECT COUNT(*) as overlapCount
       FROM od_requests
       WHERE student_id = ? AND status IN ('Approved', 'Pending')
       AND GREATEST(?, start_date) <= LEAST(?, end_date)`,
      [req.user.id, startDate, endDate]
    );

    if (leaveOverlapCheck[0].overlapCount > 0 || odOverlapCheck[0].overlapCount > 0) {
      return res.status(400).json({ error: 'Leave or OD request for these dates already exists.' });
    }

    // Get student and tutor info
    const [student] = await query('SELECT * FROM students WHERE id = ?', [req.user.id]);
    if (!student || !student.tutor_id) {
      console.error('No student or tutor ID found');
      return res.status(500).json({ error: 'Student or tutor information is missing' });
    }

    const [tutor] = await query('SELECT * FROM staff WHERE id = ?', [student.tutor_id]);
    if (!tutor) {
      console.error('Tutor not found for ID:', student.tutor_id);
      return res.status(500).json({ error: 'Tutor not found' });
    }

    // Handle photo upload if present
    let photoPath = null;
    if (req.file) {
      // Create directory structure: uploads/od-photos/{batch}/{register_number}/{date}/
      const uploadDate = new Date().toISOString().split('T')[0]; // YYYY-MM-DD
      const studentPhotoDir = path.join(__dirname, 'uploads', 'od-photos', student.batch, student.register_number.toString(), uploadDate);
      
      if (!fs.existsSync(studentPhotoDir)) {
        fs.mkdirSync(studentPhotoDir, { recursive: true });
      }
      
      const fileExtension = path.extname(req.file.originalname);
      const photoFilename = `od-${id}${fileExtension}`;
      const finalPhotoPath = path.join(studentPhotoDir, photoFilename);
      
      // Move the uploaded file to the final location
      fs.renameSync(req.file.path, finalPhotoPath);
      
      // Store the relative path for database
      photoPath = `/uploads/od-photos/${student.batch}/${student.register_number.toString()}/${uploadDate}/${photoFilename}`;
      
      console.log(`OD photo uploaded: ${photoPath}`);
    }

    await query(
      'INSERT INTO od_requests (id, student_id, student_name, student_register_number, tutor_id, tutor_name, start_date, end_date, total_days, duration_type, purpose, destination, description, photo_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [id, req.user.id, student.name, student.register_number, student.tutor_id, tutor.name, startDate, endDate, totalDays, duration_type || 'full_day', purpose, destination, description, photoPath]
    );

    // Create notifications for tutor and admin
    try {
      // Notification for tutor
      await createNotification(
        student.tutor_id,
        'New OD Request',
        `${student.name} has requested ${totalDays} day(s) for "${purpose}".`,
        'od_request',
        id,
        'od_request',
        '/tutor-od-approve'
      );

      // Notification for all admins
      const admins = await query('SELECT id FROM users WHERE is_admin = TRUE');
      for (const admin of admins) {
        await createNotification(
          admin.id,
          'New OD Request',
          `${student.name} has submitted an OD request for "${purpose}".`,
          'od_request',
          id,
          'od_request',
          '/admin-od-requests'
        );
      }
    } catch (notificationError) {
      console.error('Error creating OD request notifications:', notificationError);
      // Don't fail the request creation if notifications fail
    }

    res.status(201).json({ message: 'OD request created successfully', id });
  } catch (error) {
    console.error('OD request creation error:', error);
    res.status(500).json({ error: 'Failed to create OD request', details: error.message });
  }
});

// Update OD request status
// IMPORTANT: OD (Official Duty) requests do NOT affect student leave_taken count.
// Only leave requests affect the leave_taken field in the students table.
app.put('/od-requests/:id/status', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { status, cancelReason } = req.body;
    
    // Get the original request to check current status
    const [originalRequest] = await query('SELECT * FROM od_requests WHERE id = ?', [id]);
    if (!originalRequest) {
      return res.status(404).json({ error: 'OD request not found' });
    }
    
    // Get current user info to check permissions
    const [userProfile] = await query('SELECT is_admin, is_tutor FROM users WHERE id = ?', [req.user.id]);
    if (!userProfile) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Enforce rejection reason for admin rejections (tutors can't reject OD requests)
    if (status === 'Rejected' && userProfile.is_admin) {
      if (!cancelReason || !cancelReason.trim()) {
        return res.status(400).json({ 
          error: 'Rejection reason is required when rejecting requests.' 
        });
      }
    }

    // Business rule: Tutors cannot reject OD requests, they can only forward them
    // Only admins can reject OD requests
    if (userProfile.is_tutor && !userProfile.is_admin && status === 'Rejected') {
      return res.status(403).json({ 
        error: 'Tutors cannot reject OD requests. You can only forward OD requests to admin.' 
      });
    }
    
    // Date validation: Prevent retry or cancellation if end date has passed
    const requestEndDate = new Date(originalRequest.end_date);
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    requestEndDate.setHours(0, 0, 0, 0);
    const dateHasPassed = today > requestEndDate;
    
    if (dateHasPassed) {
      if (status === 'Retried' && originalRequest.status === 'Rejected') {
        return res.status(400).json({ 
          error: 'Cannot retry this request because the OD end date has already passed.' 
        });
      }
      if (status === 'Cancellation Pending' && 
          (originalRequest.status === 'Pending' || originalRequest.status === 'Approved' || originalRequest.status === 'Forwarded')) {
        return res.status(400).json({ 
          error: 'Cannot request cancellation because the OD end date has already passed.' 
        });
      }
    }
    
    // Set upload deadline and certificate status only after the OD has ended
    let updateQuery = 'UPDATE od_requests SET status = ?, cancel_reason = ?';
    let params = [status, cancelReason || null];
    
    if (status === 'Approved') {
      // Set certificate status to Pending Upload immediately for approved OD requests
      // No deadline restriction - users can upload certificates anytime
      updateQuery += ', certificate_status = ?';
      params.push('Pending Upload');
    }
    
    // Reset details for Retried requests
    if (status === 'Retried') {
      updateQuery += ', certificate_status = NULL, upload_deadline = NULL';
    }
    
// Handle rejection of retried requests - ensure clean status
    if (status === 'Rejected') {
      updateQuery += ', certificate_status = NULL, upload_deadline = NULL';
    }
    
    updateQuery += ' WHERE id = ?';
    params.push(id);
    
    // NOTE: We deliberately do NOT update student.leave_taken here because
    // OD requests are separate from leave requests and should not count as leave days.
    await query(updateQuery, params);
    
    const [updatedRequest] = await query('SELECT * FROM od_requests WHERE id = ?', [id]);
    res.json(updatedRequest);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to update OD request status' });
  }
});

// Profile Change Request endpoints

// Get all profile change requests (Admin only)
app.get('/profile-change-requests', authenticateToken, async (req, res) => {
  try {
    const profileChangeRequests = await query('SELECT * FROM profile_change_requests ORDER BY requested_at DESC');
    res.json(profileChangeRequests);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch profile change requests' });
  }
});

// Create profile change request
app.post('/profile-change-requests', authenticateToken, async (req, res) => {
  try {
    const { changeType, currentValue, requestedValue, reason } = req.body;
    const id = uuidv4();
    
    // Get student and tutor info
    const [student] = await query('SELECT * FROM students WHERE id = ?', [req.user.id]);
    if (!student) {
      return res.status(404).json({ error: 'Student not found' });
    }
    
    const [tutor] = await query('SELECT * FROM staff WHERE id = ?', [student.tutor_id]);
    if (!tutor) {
      return res.status(404).json({ error: 'Tutor not found' });
    }
    
    // Check if there's already a pending request for the same change type
    const [existingRequest] = await query(
      'SELECT * FROM profile_change_requests WHERE student_id = ? AND change_type = ? AND status = "Pending"',
      [req.user.id, changeType]
    );
    
    if (existingRequest) {
      return res.status(400).json({ error: `You already have a pending ${changeType} change request` });
    }
    
    await query(
      `INSERT INTO profile_change_requests 
       (id, student_id, student_name, student_register_number, tutor_id, tutor_name, 
        change_type, current_value, requested_value, reason) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [id, req.user.id, student.name, student.register_number, student.tutor_id, tutor.name, 
       changeType, currentValue, requestedValue, reason]
    );
    
    const [newRequest] = await query('SELECT * FROM profile_change_requests WHERE id = ?', [id]);
    res.status(201).json({ message: 'Profile change request created successfully', request: newRequest });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to create profile change request' });
  }
});

// Update profile change request status (Tutor/Admin only)
app.put('/profile-change-requests/:id/status', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { status, adminComments } = req.body;
    
    // Get current user info to check if they're tutor or admin
    const [userProfile] = await query('SELECT is_admin, is_tutor FROM users WHERE id = ?', [req.user.id]);
    if (!userProfile || (!userProfile.is_admin && !userProfile.is_tutor)) {
      return res.status(403).json({ error: 'Access denied. Only tutors and admins can review profile change requests.' });
    }
    
    // Get the request details
    const [request] = await query('SELECT * FROM profile_change_requests WHERE id = ?', [id]);
    if (!request) {
      return res.status(404).json({ error: 'Profile change request not found' });
    }
    
    // If tutor is trying to approve, check if it's their student
    if (userProfile.is_tutor && !userProfile.is_admin) {
      if (request.tutor_id !== req.user.id) {
        return res.status(403).json({ error: 'You can only review requests from your own students' });
      }
    }
    
    // Get reviewer info
    const [reviewer] = await query('SELECT * FROM staff WHERE id = ?', [req.user.id]);
    const reviewerName = reviewer ? reviewer.name : 'Unknown';
    
    // Update the request status
    await query(
      `UPDATE profile_change_requests 
       SET status = ?, admin_comments = ?, reviewed_at = NOW(), reviewed_by = ?, reviewer_name = ? 
       WHERE id = ?`,
      [status, adminComments || null, req.user.id, reviewerName, id]
    );
    
    // If approved, update the student's actual profile
    if (status === 'Approved') {
      let updateQuery = '';
      let updateValue = request.requested_value;
      
      switch (request.change_type) {
        case 'email':
          updateQuery = 'UPDATE students SET email = ? WHERE id = ?';
          // Also update in users table
          await query('UPDATE users SET email = ? WHERE id = ?', [updateValue, request.student_id]);
          break;
        case 'mobile':
          updateQuery = 'UPDATE students SET mobile = ? WHERE id = ?';
          break;
        case 'password':
          // TODO: remove this package import if it's not a breaking change
          //const bcrypt = require('bcryptjs');
          const hashedPassword = await bcrypt.hash(updateValue, 10);
          updateQuery = 'UPDATE users SET password_hash = ? WHERE id = ?';
          updateValue = hashedPassword;
          break;
        default:
          return res.status(400).json({ error: 'Invalid change type' });
      }
      
      await query(updateQuery, [updateValue, request.student_id]);
    }
    
    const [updatedRequest] = await query('SELECT * FROM profile_change_requests WHERE id = ?', [id]);
    res.json({ message: 'Profile change request updated successfully', request: updatedRequest });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to update profile change request status' });
  }
});

// Improved Upload OD certificate (file upload)
app.post('/api/od-requests/:id/certificate/upload', authenticateToken, certificateUpload.single('certificate'), async (req, res) => {
  try {
    const { id } = req.params;
    console.log(`Start uploading certificate for OD request ID: ${id}`);

    if (!req.file) {
      return res.status(400).json({ error: 'No certificate file uploaded' });
    }

    const { filename: tempFilename, path: tempFilePath } = req.file;
    console.log(`Uploaded file details: ${JSON.stringify(req.file)}`);

    // Get the OD request to verify it exists and get student info
    const [odRequest] = await query('SELECT * FROM od_requests WHERE id = ?', [id]);
    if (!odRequest) {
      return res.status(404).json({ error: 'OD request not found' });
    }

    // Verify the user owns this OD request
    if (odRequest.student_id !== req.user.id) {
      return res.status(403).json({ error: 'Access denied' });
    }

    // Create directory using the student's batch and register number for organization
    const [student] = await query('SELECT batch, register_number FROM students WHERE id = ?', [req.user.id]);

    // Create date-based subdirectory with new structure: uploads/{batch}/{rollnumber}/certificate/{date}
    const uploadDate = new Date().toISOString().replace(/[:.]/g, '-').substring(0, 10);
    const studentDir = path.join(__dirname, 'uploads', student.batch, student.register_number.toString(), 'certificate', uploadDate);
    
    if (!fs.existsSync(studentDir)) {
      fs.mkdirSync(studentDir, { recursive: true });
      console.log(`Created directory: ${studentDir}`);
    }

    // Create a more descriptive filename
    const fileExtension = path.extname(tempFilename);
    const descriptiveFilename = `od-${id}${fileExtension}`;
    
    const finalFilePath = path.join(studentDir, descriptiveFilename);
    fs.renameSync(tempFilePath, finalFilePath);

    console.log(`Certificate successfully stored in: ${finalFilePath}`);

    const certificateUrl = `/uploads/${student.batch}/${student.register_number.toString()}/certificate/${uploadDate}/${descriptiveFilename}`;
    await query('UPDATE od_requests SET certificate_url = ?, certificate_status = ? WHERE id = ?',
      [certificateUrl, 'Pending Verification', id]);

    const [updatedRequest] = await query('SELECT * FROM od_requests WHERE id = ?', [id]);
    res.json({ 
      ...updatedRequest, 
      certificate_url: certificateUrl,
      message: 'Certificate uploaded successfully and is now pending verification'
    });
  } catch (error) {
    console.error('Certificate upload failed:', error);
    res.status(500).json({ error: 'Failed to process certificate upload', details: error.message });
  }
});

// Upload OD certificate (URL)
app.put('/od-requests/:id/certificate', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { certificateUrl } = req.body;
    
    await query(
      'UPDATE od_requests SET certificate_url = ?, certificate_status = ? WHERE id = ?',
      [certificateUrl, 'Pending Verification', id]
    );
    
    const [updatedRequest] = await query('SELECT * FROM od_requests WHERE id = ?', [id]);
    res.json(updatedRequest);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to upload certificate' });
  }
});

// Verify OD certificate
app.put('/od-requests/:id/certificate/verify', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { isApproved } = req.body;
    const certificateStatus = isApproved ? 'Approved' : 'Rejected';
    
    await query(
      'UPDATE od_requests SET certificate_status = ? WHERE id = ?',
      [certificateStatus, id]
    );
    
    const [updatedRequest] = await query('SELECT * FROM od_requests WHERE id = ?', [id]);
    res.json(updatedRequest);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to verify certificate' });
  }
});

// Handle overdue certificates
app.put('/od-requests/handle-overdue-certificates', authenticateToken, async (req, res) => {
  try {
    const result = await query(
      `UPDATE od_requests 
       SET certificate_status = 'Overdue' 
       WHERE status = 'Approved' 
       AND certificate_status = 'Pending Upload' 
       AND upload_deadline < NOW()`
    );
    
    res.json({ 
      message: 'Overdue certificates processed successfully',
      overdueCount: result.affectedRows
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to handle overdue certificates' });
  }
});

// OD Certificate Management Functions
async function processODCertificateReminders() {
  try {
    // Get current date for comparisons
    const currentDate = new Date();
    const currentDateString = currentDate.toISOString().split('T')[0];
    
    // 0. Update approved OD requests that have ended to 'Pending Upload' status
    // No deadline restriction - users can upload certificates anytime
    const endedODRequests = await query(
      `UPDATE od_requests 
       SET certificate_status = 'Pending Upload'
       WHERE status = 'Approved' 
       AND certificate_status IS NULL
       AND end_date < CURDATE()`
    );
    
    // Skip automatic rejection - users can upload certificates without time limit
    const autoRejectCandidates = [];
    
    // Skip daily reminders within 3-day window - no deadline restrictions
    const reminderCandidates = [];
    
    // Send reminders and update notification date
    for (const request of reminderCandidates) {
      // Update last notification date
      await query(
        'UPDATE od_requests SET last_notification_date = CURDATE() WHERE id = ?',
        [request.id]
      );
      
      // In a production system, send email/push notification here
    }

    return {
      autoRejected: autoRejectCandidates.length,
      remindersSent: reminderCandidates.length
    };
  } catch (error) {
    console.error('Error in OD certificate reminder job:', error);
    throw error;
  }
}

// Enhanced function to calculate leave taken - properly handles half-day leaves
async function calculateLeaveTaken(studentId) {
  try {
    // Get all approved leave requests with duration type for proper calculation
    const leaveRequests = await query(
      `SELECT total_days, duration_type, start_date, end_date
       FROM leave_requests
       WHERE student_id = ? AND status = 'Approved'
       AND start_date <= CURDATE()`,
      [studentId]
    );
    
    let totalLeave = 0;
    
    for (const request of leaveRequests) {
      let leaveDaysForThisRequest = 0;
      
      if (request.duration_type === 'half_day_forenoon' || request.duration_type === 'half_day_afternoon') {
        // For half-day requests, calculate 0.5 days per day in the date range
        const startDate = new Date(request.start_date);
        const endDate = new Date(request.end_date);
        const timeDifference = endDate.getTime() - startDate.getTime();
        const daysDifference = Math.ceil(timeDifference / (1000 * 3600 * 24)) + 1;
        leaveDaysForThisRequest = daysDifference * 0.5;
      } else {
        // For full-day requests, use total_days as is (should be integer)
        leaveDaysForThisRequest = parseFloat(request.total_days) || 0;
      }
      
      totalLeave += leaveDaysForThisRequest;
    }
    
    // Only log in development mode to prevent console spam
    if (process.env.NODE_ENV === 'development') {
      console.log(`Leave calculation for student ${studentId}: ${totalLeave} days (from ${leaveRequests.length} requests)`);
    }
    
    // Return the total as a float, formatted to 1 decimal place
    return Math.round(totalLeave * 10) / 10;
  } catch (error) {
    console.error('Error calculating leave taken for student', studentId, ':', error.message);
    // Return 0 instead of throwing to prevent cascade failures
    return 0;
  }
}

// Get OD certificate reminders for logged-in user
app.get('/notifications/od-certificate-reminders', authenticateToken, async (req, res) => {
  try {
    // Get all approved OD requests that need certificate upload (no deadline restriction)
    const reminders = await query(
      `SELECT * FROM od_requests 
       WHERE student_id = ? 
       AND status = 'Approved' 
       AND certificate_status = 'Pending Upload'
       AND end_date < CURDATE()`,
      [req.user.id]
    );
    
    const reminderData = reminders.map(request => {
      const endDate = new Date(request.end_date);
      const currentDate = new Date();
      const daysSinceEnd = Math.ceil((currentDate - endDate) / (1000 * 60 * 60 * 24));
      
      return {
        id: request.id,
        purpose: request.purpose,
        destination: request.destination,
        endDate: request.end_date,
        daysSinceEnd: daysSinceEnd,
        message: 'Certificate upload pending - no deadline restrictions'
      };
    });
    
    res.json({
      reminders: reminderData,
      count: reminderData.length
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch certificate reminders' });
  }
});

// Manual trigger for OD certificate processing (Admin only)
app.post('/admin/process-od-certificates', authenticateToken, async (req, res) => {
  try {
    // Check if user is admin
    const [user] = await query(
      'SELECT is_admin FROM users WHERE id = ?',
      [req.user.id]
    );
    
    if (!user || !user.is_admin) {
      return res.status(403).json({ error: 'Access denied. Admin privileges required.' });
    }
    
    const result = await processODCertificateReminders();
    
    res.json({
      message: 'OD certificate processing completed',
      autoRejected: result.autoRejected,
      remindersSent: result.remindersSent
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to process OD certificates' });
  }
});

// Admin utility to audit and fix student leave counts (Admin only)
app.post('/admin/audit-leave-counts', authenticateToken, async (req, res) => {
  try {
    // Check if user is admin
    const [user] = await query(
      'SELECT is_admin FROM users WHERE id = ?',
      [req.user.id]
    );
    
    if (!user || !user.is_admin) {
      return res.status(403).json({ error: 'Access denied. Admin privileges required.' });
    }
    
    // Find students with incorrect leave counts
    const studentsWithIssues = await query(`
      SELECT 
        s.id,
        s.name,
        s.leave_taken as current_count,
        COALESCE(SUM(CASE WHEN lr.status = 'Approved' THEN lr.total_days ELSE 0 END), 0) as correct_count
      FROM students s 
      LEFT JOIN leave_requests lr ON s.id = lr.student_id 
      GROUP BY s.id, s.name, s.leave_taken 
      HAVING s.leave_taken != correct_count
    `);
    
    const fixedStudents = [];
    
    // Fix each student's leave count
    for (const student of studentsWithIssues) {
      await query(
        'UPDATE students SET leave_taken = ? WHERE id = ?',
        [student.correct_count, student.id]
      );
      
      fixedStudents.push({
        name: student.name,
        old_count: student.current_count,
        new_count: student.correct_count,
        difference: student.current_count - student.correct_count
      });
    }
    
    res.json({
      message: `Leave count audit completed. Fixed ${fixedStudents.length} students.`,
      fixed_students: fixedStudents,
      total_fixed: fixedStudents.length
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to audit leave counts' });
  }
});


// Test database connection
app.get('/test-db', async (req, res) => {
  try {
    const [result] = await query('SELECT COUNT(*) as count FROM users');
    res.json({ success: true, userCount: result.count, message: 'Database connection successful' });
  } catch (error) {
    console.error('Database test failed:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Temporary test endpoint to get sample users
app.get('/test-users', async (req, res) => {
  try {
    const users = await query('SELECT id, email, first_name, last_name, is_admin, is_tutor FROM users LIMIT 5');
    const students = await query('SELECT id, register_number, name, email FROM students LIMIT 3');
    res.json({ 
      success: true,
      users: users,
      students: students
    });
  } catch (error) {
    console.error('Failed to fetch test users:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to fetch test users',
      details: error.message 
    });
  }
});

// Temporary endpoint to create test user
app.post('/create-test-user', async (req, res) => {
  try {
    const testEmail = 'testupload@college.portal';
    const testPassword = 'testpassword123';
    const testRegNumber = '9999';
    const testName = 'Test Upload User';
    
    // Check if user already exists
    const [existingUser] = await query('SELECT id FROM users WHERE email = ?', [testEmail]);
    if (existingUser) {
      return res.json({ 
        success: true, 
        message: 'Test user already exists',
        email: testEmail,
        password: testPassword,
        register_number: testRegNumber
      });
    }
    
    const id = uuidv4();
    const passwordHash = await bcrypt.hash(testPassword, 10);
    
    // Insert into users table
    await query(
      'INSERT INTO users (id, email, password_hash, first_name, last_name) VALUES (?, ?, ?, ?, ?)',
      [id, testEmail, passwordHash, 'Test Upload', 'User']
    );
    
    // Insert into students table
    await query(
      'INSERT INTO students (id, name, register_number, email, tutor_id, batch, semester, mobile) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [id, testName, testRegNumber, testEmail, '2ef0a367-4cb8-4865-b65f-1def7b8161d2', 'Test', 1, '1234567890']
    );
    
    res.json({ 
      success: true, 
      message: 'Test user created successfully',
      email: testEmail,
      password: testPassword,
      register_number: testRegNumber
    });
  } catch (error) {
    console.error('Failed to create test user:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to create test user',
      details: error.message 
    });
  }
});

// Temporary endpoint to create staff record for tutor
app.post('/create-staff-for-tutor', async (req, res) => {
  try {
    const tutorId = '2ef0a367-4cb8-4865-b65f-1def7b8161d2';
    
    // Check if staff record already exists
    const [existingStaff] = await query('SELECT id FROM staff WHERE id = ?', [tutorId]);
    if (existingStaff) {
      return res.json({ 
        success: true, 
        message: 'Staff record already exists for tutor'
      });
    }
    
    // Get user info for the tutor
    const [tutorUser] = await query('SELECT * FROM users WHERE id = ?', [tutorId]);
    if (!tutorUser) {
      return res.status(404).json({ 
        success: false, 
        error: 'Tutor user not found'
      });
    }
    
    // Insert into staff table
    await query(
      'INSERT INTO staff (id, name, email, username, is_admin, is_tutor) VALUES (?, ?, ?, ?, ?, ?)',
      [tutorId, `${tutorUser.first_name} ${tutorUser.last_name}`, tutorUser.email, 'tutor1', tutorUser.is_admin, tutorUser.is_tutor]
    );
    
    res.json({ 
      success: true, 
      message: 'Staff record created for tutor successfully'
    });
  } catch (error) {
    console.error('Failed to create staff record:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to create staff record',
      details: error.message 
    });
  }
});

// Temporary endpoint to get test user details
app.get('/test-student-details', async (req, res) => {
  try {
    const testEmail = 'testupload@college.portal';
    
    // Get user info
    const [user] = await query('SELECT * FROM users WHERE email = ?', [testEmail]);
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        error: 'Test user not found'
      });
    }
    
    // Get student info
    const [student] = await query('SELECT * FROM students WHERE id = ?', [user.id]);
    
    // Get tutor info if exists
    let tutor = null;
    if (student && student.tutor_id) {
      [tutor] = await query('SELECT * FROM staff WHERE id = ?', [student.tutor_id]);
    }
    
    res.json({ 
      success: true,
      user: user,
      student: student,
      tutor: tutor
    });
  } catch (error) {
    console.error('Failed to get test student details:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to get test student details',
      details: error.message 
    });
  }
});

// Temporary endpoint to assign tutor to test student
app.post('/assign-tutor-to-test-student', async (req, res) => {
  try {
    console.log('Assigning tutor to test student...');
    
    const tutorEmail = 'test@ace.com';
    const testEmail = 'testupload@college.portal';
    
    // Find the tutor by email in users table
    const [tutorUser] = await query('SELECT id FROM users WHERE email = ?', [tutorEmail]);
    
    if (!tutorUser) {
      return res.json({ success: false, error: `Tutor user not found with email ${tutorEmail}` });
    }
    
    const tutorId = tutorUser.id;
    console.log('Found tutor ID:', tutorId);
    
    // Check if student record exists
    const [existingStudent] = await query('SELECT * FROM students WHERE email = ?', [testEmail]);
    
    if (!existingStudent) {
      // Get test user info to create student record
      const [testUser] = await query('SELECT * FROM users WHERE email = ?', [testEmail]);
      if (!testUser) {
        return res.json({ success: false, error: 'Test user not found' });
      }
      
      // Create student record if it doesn't exist
      await query(
        'INSERT INTO students (id, name, register_number, email, tutor_id, batch, semester, mobile) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        [testUser.id, `${testUser.first_name} ${testUser.last_name}`, 'TEST001', testEmail, tutorId, 'Test', 1, '1234567890']
      );
      console.log('Created new student record with tutor assigned');
    } else {
      // Update existing student record
      await query('UPDATE students SET tutor_id = ? WHERE email = ?', [tutorId, testEmail]);
      console.log('Updated existing student record with tutor');
    }
    
    res.json({ success: true, message: 'Tutor assigned successfully', tutorId: tutorId });
  } catch (error) {
    console.error('Error assigning tutor to test student:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get email by username (RPC function replacement)
app.get('/users/email-by-username/:username', async (req, res) => {
  try {
    const { username } = req.params;
    
    // Check in staff table for username
    const [staffMember] = await query('SELECT email FROM staff WHERE username = ?', [username]);
    if (staffMember) {
      return res.json({ email: staffMember.email });
    }
    
    // Check in students table for username
    const [student] = await query('SELECT * FROM students WHERE username = ?', [username]);
    if (student) {
      const email = `${username}@college.portal`; // Default email format
      return res.json({ email });
    }
    
    res.status(404).json({ error: 'Username not found' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to lookup username' });
  }
});

// Login with username or email with OTP VERIFICATION
app.post('/auth/login', async (req, res) => {
  try {
    const { identifier, password } = req.body;
    let user;
    
    console.log(`🔐 === LOGIN ATTEMPT ===`);
    console.log(`Identifier: ${identifier}`);
    console.log(`IP: ${req.ip}`);
    
    // Check if identifier is email or username
    if (identifier.includes('@')) {
      [user] = await query('SELECT * FROM users WHERE email = ?', [identifier]);
    } else {
      // Check in staff table for username (staff still have usernames)
      const [staffMember] = await query('SELECT * FROM staff WHERE username = ?', [identifier]);
      if (staffMember) {
        [user] = await query('SELECT * FROM users WHERE id = ?', [staffMember.id]);
      }
      // Students no longer have usernames, they must login with email
    }
    
    if (!user || !await bcrypt.compare(password, user.password_hash)) {
      console.log(`❌ Invalid credentials for: ${identifier}`);
      return res.status(401).json({ error: 'Invalid username or password' });
    }
    
    console.log(`✅ Credentials verified for user: ${user.id}`);
    
    // Invalidate all existing sessions for this user (single session enforcement)
    await invalidateUserSessions(user.id);
    
    // Clean up expired sessions
    await cleanupExpiredSessions();
    
    // Create new token and session (but OTP not verified yet)
    const token = jwt.sign({ id: user.id, is_admin: user.is_admin, is_tutor: user.is_tutor }, jwtSecret, { expiresIn: '24h' });
    await createSession(user.id, token);
    
    // Reset OTP verification status for new login
    const { default: otpManager } = await import('./utils/otpUtils.js');
    await otpManager.resetOTPVerification(user.id);
    
    // Get user details for the email notification
    let userName = user.email; // Default to email
    if (user.is_admin || user.is_tutor) {
      // For staff, get their name from staff table
      try {
        const [staff] = await query('SELECT name FROM staff WHERE id = ?', [user.id]);
        if (staff) userName = staff.name;
      } catch (staffError) {
        console.warn('Could not get staff name:', staffError);
      }
    } else {
      // For students, get their name from students table
      try {
        const [student] = await query('SELECT name FROM students WHERE id = ?', [user.id]);
        if (student) userName = student.name;
      } catch (studentError) {
        console.warn('Could not get student name:', studentError);
      }
    }
    
    // Send login notification email (non-blocking)
    setImmediate(async () => {
      console.log('🔄 Starting login notification process...');
      console.log('📧 Target email:', user.email);
      console.log('👤 User name:', userName);
      
      try {
        // Check environment variables are available
        console.log('🔧 Environment check:');
        console.log('   EMAIL_USER:', process.env.EMAIL_USER ? '✅ Set' : '❌ Missing');
        console.log('   EMAIL_PASSWORD:', process.env.EMAIL_PASSWORD ? '✅ Set' : '❌ Missing');
        
        if (!process.env.EMAIL_USER || !process.env.EMAIL_PASSWORD) {
          throw new Error('Email configuration missing - EMAIL_USER or EMAIL_PASSWORD not set');
        }
        
        const loginDetails = {
          ipAddress: req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'] || 'Unknown',
          userAgent: req.headers['user-agent'] || 'Unknown'
        };
        
        console.log('🌐 Login details:');
        console.log('   IP Address:', loginDetails.ipAddress);
        console.log('   User Agent:', loginDetails.userAgent.substring(0, 50) + '...');
        
        console.log('📨 Attempting to send email notification...');
        const emailResult = await sendLoginNotification(user.email, userName, loginDetails);
        
        if (emailResult && emailResult.success) {
          console.log('✅ Login notification email sent successfully!');
          console.log('   Message ID:', emailResult.messageId);
          console.log('   Sent to:', user.email);
        } else {
          console.error('❌ Email sending failed:', emailResult?.error || 'Unknown error');
        }
        
      } catch (emailError) {
        console.error('❌ DETAILED EMAIL ERROR:');
        console.error('   Error message:', emailError.message);
        console.error('   Error stack:', emailError.stack);
        console.error('   Error code:', emailError.code);
        
        // Additional debugging info
        if (emailError.code === 'EAUTH') {
          console.error('🔐 AUTHENTICATION ERROR - Check Gmail app password!');
        } else if (emailError.code === 'ECONNREFUSED') {
          console.error('🔌 CONNECTION REFUSED - Check internet/firewall!');
        } else if (emailError.code === 'ETIMEDOUT') {
          console.error('⏰ TIMEOUT ERROR - Network/DNS issue!');
        }
        
        // Don't block the login process if email fails
      }
    });
    
    console.log(`🔐 Login successful for user: ${user.id}, OTP verification required`);
    console.log(`🔐 === LOGIN COMPLETE ===`);
    
    res.json({ 
      token, 
      user: { id: user.id, email: user.email, userName: userName },
      requiresOTP: true,
      message: 'Login successful. Please complete OTP verification to access your account.'
    });
  } catch (error) {
    console.error('❌ Login error:', error);
    res.status(500).json({ error: 'Failed to login' });
  }
});

// Logout endpoint
app.post('/auth/logout', authenticateToken, async (req, res) => {
  try {
    const tokenHash = crypto.createHash('sha256').update(req.token).digest('hex');
    
    // Invalidate the current session
    await query(
      'UPDATE user_sessions SET is_active = 0 WHERE token_hash = ?',
      [tokenHash]
    );
    
    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to logout' });
  }
});

// Profile change notifications endpoint
app.post('/notifications/profile-change', authenticateToken, async (req, res) => {
  try {
    const { changeType, oldValue, newValue, reason, message } = req.body;
    
    // Get current user info
    const [currentUserProfile] = await query('SELECT is_admin, is_tutor FROM users WHERE id = ?', [req.user.id]);
    const isStudent = !currentUserProfile.is_admin && !currentUserProfile.is_tutor;
    
    if (isStudent) {
      // Student profile change - notify tutor and admin
      const [student] = await query('SELECT * FROM students WHERE id = ?', [req.user.id]);
      if (student) {
        console.log(`NOTIFICATION: Student ${student.name} changed their ${changeType} from '${oldValue}' to '${newValue}'. Reason: ${reason}`);
        // Here you would implement actual email/push notifications to tutor and admin
      }
    } else if (currentUserProfile.is_tutor && !currentUserProfile.is_admin) {
      // Tutor profile change - notify admin
      const [tutor] = await query('SELECT * FROM staff WHERE id = ?', [req.user.id]);
      if (tutor) {
        console.log(`NOTIFICATION: Tutor ${tutor.name} changed their ${changeType} from '${oldValue}' to '${newValue}'. Reason: ${reason}`);
        // Here you would implement actual email/push notifications to admin
      }
    }
    
    res.json({ message: 'Notification sent successfully' });
  } catch (error) {
    console.error('Error sending profile change notification:', error);
    res.status(500).json({ error: 'Failed to send notification' });
  }
});

// ===============================================================================
// NOTIFICATION SYSTEM - COMPLETELY REBUILT
// ===============================================================================

/**
 * Create a single notification for a user
 */
async function createNotification(userId, title, message, type = 'system', referenceId = null, referenceType = null, actionUrl = null) {
  try {
    const notificationId = uuidv4();
    
    await query(
      `INSERT INTO notifications (id, user_id, title, message, type, reference_id, reference_type, action_url, is_read, created_at) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, NOW())`,
      [notificationId, userId, title, message, type, referenceId, referenceType, actionUrl]
    );
    
    console.log(`✅ Notification created: ${notificationId} for user ${userId}`);
    return notificationId;
  } catch (error) {
    console.error('❌ Error creating notification:', error);
    throw error;
  }
}

/**
 * Create notifications for multiple users
 */
async function createNotificationForUsers(userIds, title, message, type = 'system', referenceId = null, referenceType = null, actionUrl = null) {
  const notifications = [];
  for (const userId of userIds) {
    try {
      const notificationId = await createNotification(userId, title, message, type, referenceId, referenceType, actionUrl);
      notifications.push({ id: notificationId, userId });
    } catch (error) {
      console.error(`❌ Failed to create notification for user ${userId}:`, error);
    }
  }
  return notifications;
}

// Get notifications for the current user (max 5 unread, then others)
app.get('/api/notifications', authenticateToken, async (req, res) => {
  try {
    // Get unread notifications first (max 5)
    const unreadNotifications = await query(
      `SELECT * FROM notifications 
       WHERE user_id = ? AND is_read = FALSE 
       ORDER BY created_at DESC 
       LIMIT 5`,
      [req.user.id]
    );

    // If we have less than 5 unread, fill with recent read notifications
    let readNotifications = [];
    if (unreadNotifications.length < 5) {
      const remainingSlots = 5 - unreadNotifications.length;
      readNotifications = await query(
        `SELECT * FROM notifications 
         WHERE user_id = ? AND is_read = TRUE 
         ORDER BY read_at DESC 
         LIMIT ?`,
        [req.user.id, remainingSlots]
      );
    }

    const allNotifications = [...unreadNotifications, ...readNotifications];
    
    res.json({
      notifications: allNotifications,
      unreadCount: unreadNotifications.length,
      totalCount: allNotifications.length
    });
  } catch (error) {
    console.error('Error fetching notifications:', error);
    res.status(500).json({ error: 'Failed to fetch notifications' });
  }
});

// Mark a specific notification as read
app.put('/api/notifications/:id/read', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Verify the notification belongs to the current user
    const [notification] = await query(
      'SELECT * FROM notifications WHERE id = ? AND user_id = ?',
      [id, req.user.id]
    );
    
    if (!notification) {
      return res.status(404).json({ error: 'Notification not found' });
    }
    
    if (notification.is_read) {
      return res.json({ message: 'Notification already marked as read' });
    }
    
    // Mark as read
    await query(
      'UPDATE notifications SET is_read = TRUE, read_at = NOW() WHERE id = ?',
      [id]
    );
    
    res.json({ message: 'Notification marked as read' });
  } catch (error) {
    console.error('Error marking notification as read:', error);
    res.status(500).json({ error: 'Failed to mark notification as read' });
  }
});

// Mark all notifications as read
app.put('/api/notifications/mark-all-read', authenticateToken, async (req, res) => {
  try {
    await query(
      'UPDATE notifications SET is_read = TRUE, read_at = NOW() WHERE user_id = ? AND is_read = FALSE',
      [req.user.id]
    );
    
    res.json({ message: 'All notifications marked as read' });
  } catch (error) {
    console.error('Error marking all notifications as read:', error);
    res.status(500).json({ error: 'Failed to mark all notifications as read' });
  }
});

// Get unread notification count
app.get('/api/notifications/unread-count', authenticateToken, async (req, res) => {
  try {
    const [result] = await query(
      'SELECT COUNT(*) as count FROM notifications WHERE user_id = ? AND is_read = FALSE',
      [req.user.id]
    );
    
    res.json({ unreadCount: result.count });
  } catch (error) {
    console.error('Error fetching unread count:', error);
    res.status(500).json({ error: 'Failed to fetch unread count' });
  }
});




// Setup daily cron job for OD certificate reminders
// Runs every day at 9:00 AM
cron.schedule('0 9 * * *', async () => {
  try {
    await processODCertificateReminders();
  } catch (error) {
    console.error('Error in daily OD certificate reminder cron job:', error);
  }
});

// Weekly Leave Data Endpoint
app.get('/api/leave-data/weekly', authenticateToken, async (req, res) => {
  try {
    const approvedLeaves = await query('SELECT * FROM leave_requests WHERE status = "Approved"');
    const students = await query('SELECT id, batch FROM students');

    const weeklyData = {};
    const today = new Date();

    approvedLeaves.forEach(leave => {
      const student = students.find(s => s.id === leave.student_id);
      if (!student) return;

      const leaveStart = new Date(leave.start_date);
      const leaveEnd = new Date(leave.end_date);

      const currDate = new Date(leaveStart);
      while (currDate <= leaveEnd) {
        if (currDate > today) {
          break; // Skip future dates
        }
        const week = `${currDate.getFullYear()}-W${getWeekOfYear(currDate)}`;
        if (!weeklyData[week]) {
          weeklyData[week] = {};
        }
        if (!weeklyData[week][student.batch]) {
          weeklyData[week][student.batch] = 0;
        }
        weeklyData[week][student.batch] += 1;
        currDate.setDate(currDate.getDate() + 1);
      }
    });

    res.json(weeklyData);
  } catch (error) {
    console.error('Failed to fetch weekly leave data:', error);
    res.status(500).json({ error: 'Failed to fetch weekly leave data' });
  }
});

// Daily Leave Data Endpoint
app.get('/api/leave-data/daily', authenticateToken, async (req, res) => {
  try {
    const approvedLeaves = await query('SELECT * FROM leave_requests WHERE status = "Approved"');
    const students = await query('SELECT id FROM students');

    const dailyData = {};
    const today = new Date();

    approvedLeaves.forEach(leave => {
      const student = students.find(s => s.id === leave.student_id);
      if (!student) return;

      const leaveStart = new Date(leave.start_date);
      const leaveEnd = new Date(leave.end_date);

      const currDate = new Date(leaveStart);
      while (currDate <= leaveEnd) {
        if (currDate > today) {
          break; // Skip future dates
        }
        const date = currDate.toISOString().split('T')[0];
        if (!dailyData[date]) {
          dailyData[date] = 0;
        }
        dailyData[date] += 1;
        currDate.setDate(currDate.getDate() + 1);
      }
    });

    res.json(dailyData);
  } catch (error) {
    console.error('Failed to fetch daily leave data:', error);
    res.status(500).json({ error: 'Failed to fetch daily leave data' });
  }
});

// Profile Photo Upload Endpoint
app.post('/api/profile-photo', authenticateToken, profileUpload.single('profilePhoto'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const userId = req.user.id;
    
    // First, check what type of user this is
    const [user] = await query('SELECT is_admin, is_tutor FROM users WHERE id = ?', [userId]);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    let userProfileDir;
    let profilePhotoUrl;
    
    if (user.is_admin || user.is_tutor) {
      // For staff members (tutors/admins)
      const [staff] = await query('SELECT name FROM staff WHERE id = ?', [userId]);
      if (!staff) {
        return res.status(404).json({ error: 'Staff record not found' });
      }
      
      if (user.is_admin) {
        // For admins, use simple structure: uploads/Admin/profile.png
        userProfileDir = path.join(__dirname, 'uploads', 'Admin');
        profilePhotoUrl = `/uploads/Admin/profile.png`;
      } else {
        // For tutors, use simplified structure: uploads/{tutor_name}/profile.png
        const sanitizedName = staff.name.replace(/[^a-zA-Z0-9\s-]/g, '').replace(/\s+/g, '-').toLowerCase();
        userProfileDir = path.join(__dirname, 'uploads', sanitizedName);
        profilePhotoUrl = `/uploads/${sanitizedName}/profile.png`;
      }
    } else {
      // For students, use batch/rollnumber structure
      const [student] = await query('SELECT batch, register_number FROM students WHERE id = ?', [userId]);
      if (!student) {
        return res.status(404).json({ error: 'Student record not found' });
      }
      
      // Create directory structure: uploads/{batch}/{rollnumber}/profile/
      userProfileDir = path.join(__dirname, 'uploads', student.batch, student.register_number.toString(), 'profile');
      profilePhotoUrl = `/uploads/${student.batch}/${student.register_number}/profile/profile.png`;
    }
    
    // Create the directory if it doesn't exist
    if (!fs.existsSync(userProfileDir)) {
      fs.mkdirSync(userProfileDir, { recursive: true });
    }

    // Check if old profile photo exists and delete it
    const finalFilePath = path.join(userProfileDir, 'profile.png');
    if (fs.existsSync(finalFilePath)) {
      try {
        fs.unlinkSync(finalFilePath);
        console.log(`Deleted old profile photo: ${finalFilePath}`);
      } catch (deleteError) {
        console.warn('Failed to delete old profile photo:', deleteError);
      }
    }

    // Process and save the new image as profile.png
    const tempFilePath = req.file.path;
    await sharp(tempFilePath)
      .png({ quality: 90 }) // Convert to PNG format
      .toFile(finalFilePath);
    
    // Remove the temporary file
    fs.unlinkSync(tempFilePath);

    // Update the user's profile photo in the database
    try {
      // Update the users table with the new profile photo
      await query('UPDATE users SET profile_photo = ? WHERE id = ?', [profilePhotoUrl, userId]);

      // Also update the appropriate table (students or staff)
      if (user.is_admin || user.is_tutor) {
        // Update staff table
        await query('UPDATE staff SET profile_photo = ? WHERE id = ?', [profilePhotoUrl, userId]);
      } else {
        // Update students table
        await query('UPDATE students SET profile_photo = ? WHERE id = ?', [profilePhotoUrl, userId]);
      }

      console.log(`Profile photo updated for user ${userId}: ${profilePhotoUrl}`);

    } catch (dbError) {
      console.error('Database update error:', dbError);
      // If database update fails, we should delete the uploaded file
      try {
        fs.unlinkSync(finalFilePath);
      } catch (deleteError) {
        console.error('Failed to delete uploaded file after database error:', deleteError);
      }
      return res.status(500).json({ error: 'Failed to update profile photo in database' });
    }

    res.json({ 
      message: 'Profile photo uploaded and updated successfully', 
      path: profilePhotoUrl 
    });

  } catch (error) {
    console.error('Profile photo upload failed:', error);
    res.status(500).json({ error: 'Failed to upload profile photo' });
  }
});


// Helper function to get week of year
function getWeekOfYear(date) {
  const oneJan = new Date(date.getFullYear(), 0, 1);
  const numberOfDays = Math.floor((date - oneJan) / (24 * 60 * 60 * 1000));
  return Math.ceil((date.getDay() + 1 + numberOfDays) / 7);
}

// Debug endpoint to test leave calculation for specific student
app.get('/debug/student/:id/leave-calculation', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Get student info
    const [student] = await query('SELECT * FROM students WHERE id = ?', [id]);
    if (!student) {
      return res.status(404).json({ error: 'Student not found' });
    }
    
    // Get all leave requests for this student
    const allLeaves = await query(
      `SELECT id, status, start_date, end_date, total_days, created_at, 
              DATE(start_date) as start_date_only, DATE(NOW()) as today_date,
              CASE WHEN DATE(start_date) <= DATE(NOW()) THEN 'INCLUDED' ELSE 'EXCLUDED' END as inclusion_status
       FROM leave_requests
       WHERE student_id = ?
       ORDER BY created_at DESC`,
      [id]
    );
    
    // Get approved leaves within date range
    const [approvedLeaves] = await query(
      `SELECT COALESCE(SUM(total_days), 0) as leaveTaken,
              COUNT(*) as approvedCount
       FROM leave_requests
       WHERE student_id = ?
       AND status = 'Approved'
       AND DATE(start_date) <= DATE(NOW())`,
      [id]
    );
    
    // Calculate using the function
    const dynamicLeaveTaken = await calculateLeaveTaken(id);
    
    res.json({
      student: {
        id: student.id,
        name: student.name,
        register_number: student.register_number,
        stored_leave_taken: student.leave_taken
      },
      current_date: new Date().toISOString().split('T')[0],
      all_leave_requests: allLeaves,
      approved_summary: {
        total_approved_days: approvedLeaves.leaveTaken,
        approved_requests_count: approvedLeaves.approvedCount
      },
      dynamic_calculation_result: dynamicLeaveTaken,
      matches_expected: dynamicLeaveTaken === approvedLeaves.leaveTaken
    });
  } catch (error) {
    console.error('Debug leave calculation error:', error);
    res.status(500).json({ error: 'Failed to debug leave calculation', details: error.message });
  }
});

// =====================================================================================
// OTP VERIFICATION SYSTEM INTEGRATION
// =====================================================================================
// Import and setup OTP routes
import otpAuthRoutes from './routes/otpAuth.js';
import { requireOTPVerification } from './middleware/otpAuth.js';

// OTP Authentication Routes (requires JWT but not OTP verification)
app.use('/api/otp', otpAuthRoutes);

// Apply OTP verification middleware to protected routes
// Note: Update existing routes to use requireOTPVerification instead of authenticateToken
// where OTP verification is required

console.log('✅ OTP Verification System Integrated');
console.log('📧 OTP routes available at: /api/otp/*');
console.log('🔐 OTP verification required for protected routes');

// Create test tutor endpoint
app.post('/create-test-tutor', async (req, res) => {
  try {
    const testEmail = 'testtutor@college.portal';
    const testPassword = 'testpassword123';
    const testName = 'Test Tutor';
    
    // Check if user already exists
    const [existingUser] = await query('SELECT id FROM users WHERE email = ?', [testEmail]);
    if (existingUser) {
      return res.json({ 
        success: true, 
        message: 'Test tutor already exists',
        email: testEmail,
        password: testPassword,
        id: existingUser.id
      });
    }
    
    const id = uuidv4();
    const passwordHash = await bcrypt.hash(testPassword, 10);
    
    // Insert into users table
    await query(
      'INSERT INTO users (id, email, password_hash, first_name, last_name, is_admin, is_tutor) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [id, testEmail, passwordHash, 'Test', 'Tutor', false, true]
    );
    
    // Insert into staff table
    await query(
      'INSERT INTO staff (id, name, email, username, is_admin, is_tutor) VALUES (?, ?, ?, ?, ?, ?)',
      [id, testName, testEmail, 'testtutor', false, true]
    );
    
    res.json({ 
      success: true, 
      message: 'Test tutor created successfully',
      email: testEmail,
      password: testPassword,
      id: id
    });
  } catch (error) {
    console.error('Failed to create test tutor:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to create test tutor',
      details: error.message 
    });
  }
});

// =====================================================================================
// EXCEPTION DAYS API ENDPOINTS
// =====================================================================================

// Get all exception days (Admin only)
app.get('/api/exception-days', authenticateToken, express.json(), async (req, res) => {
  try {
    // Only admins can manage exception days
    const [user] = await query('SELECT is_admin FROM users WHERE id = ?', [req.user.id]);
    if (!user || !user.is_admin) {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const exceptionDays = await query(
      'SELECT * FROM exception_days ORDER BY date DESC'
    );
    
    res.json(exceptionDays);
  } catch (error) {
    console.error('Error fetching exception days:', error);
    res.status(500).json({ error: 'Failed to fetch exception days' });
  }
});

// Get exception days for students/tutors (public read access)
app.get('/api/exception-days/public', authenticateToken, async (req, res) => {
  try {
    // All authenticated users can view exception days to avoid applying leave on blocked dates
    const exceptionDays = await query(
      'SELECT date, reason FROM exception_days WHERE date >= CURDATE() ORDER BY date ASC'
    );
    
    res.json(exceptionDays);
  } catch (error) {
    console.error('Error fetching public exception days:', error);
    res.status(500).json({ error: 'Failed to fetch exception days' });
  }
});

// Create new exception day
app.post('/api/exception-days', authenticateToken, express.json(), async (req, res) => {
  try {
    // Only admins can manage exception days
    const [user] = await query('SELECT is_admin FROM users WHERE id = ?', [req.user.id]);
    if (!user || !user.is_admin) {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { date, reason, description } = req.body;
    
    if (!date || !reason) {
      return res.status(400).json({ error: 'Date and reason are required' });
    }

    // Check if date already exists
    const [existingDay] = await query(
      'SELECT id FROM exception_days WHERE date = ?',
      [date]
    );
    
    if (existingDay) {
      return res.status(400).json({ error: 'Exception day already exists for this date' });
    }

    const id = uuidv4();
    await query(
      'INSERT INTO exception_days (id, date, reason, description) VALUES (?, ?, ?, ?)',
      [id, date, reason, description || null]
    );
    
    // Return the created exception day
    const [newExceptionDay] = await query(
      'SELECT * FROM exception_days WHERE id = ?',
      [id]
    );
    
    res.status(201).json(newExceptionDay);
  } catch (error) {
    console.error('Error creating exception day:', error);
    res.status(500).json({ error: 'Failed to create exception day' });
  }
});

// Update exception day
app.put('/api/exception-days/:id', authenticateToken, express.json(), async (req, res) => {
  try {
    // Only admins can manage exception days
    const [user] = await query('SELECT is_admin FROM users WHERE id = ?', [req.user.id]);
    if (!user || !user.is_admin) {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { id } = req.params;
    const { date, reason, description } = req.body;
    
    if (!date || !reason) {
      return res.status(400).json({ error: 'Date and reason are required' });
    }

    // Check if exception day exists
    const [existingDay] = await query(
      'SELECT id FROM exception_days WHERE id = ?',
      [id]
    );
    
    if (!existingDay) {
      return res.status(404).json({ error: 'Exception day not found' });
    }

    // Check if new date conflicts with other exception days (excluding current one)
    const [conflictingDay] = await query(
      'SELECT id FROM exception_days WHERE date = ? AND id != ?',
      [date, id]
    );
    
    if (conflictingDay) {
      return res.status(400).json({ error: 'Another exception day already exists for this date' });
    }

    await query(
      'UPDATE exception_days SET date = ?, reason = ?, description = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [date, reason, description || null, id]
    );
    
    // Return the updated exception day
    const [updatedExceptionDay] = await query(
      'SELECT * FROM exception_days WHERE id = ?',
      [id]
    );
    
    res.json(updatedExceptionDay);
  } catch (error) {
    console.error('Error updating exception day:', error);
    res.status(500).json({ error: 'Failed to update exception day' });
  }
});

// Delete exception day
app.delete('/api/exception-days/:id', authenticateToken, express.json(), async (req, res) => {
  try {
    // Only admins can manage exception days
    const [user] = await query('SELECT is_admin FROM users WHERE id = ?', [req.user.id]);
    if (!user || !user.is_admin) {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { id } = req.params;
    
    // Check if exception day exists
    const [existingDay] = await query(
      'SELECT id FROM exception_days WHERE id = ?',
      [id]
    );
    
    if (!existingDay) {
      return res.status(404).json({ error: 'Exception day not found' });
    }

    await query('DELETE FROM exception_days WHERE id = ?', [id]);
    
    res.json({ message: 'Exception day deleted successfully' });
  } catch (error) {
    console.error('Error deleting exception day:', error);
    res.status(500).json({ error: 'Failed to delete exception day' });
  }
});

// Check if a specific date is an exception day (for use in leave/OD validation)
app.get('/api/exception-days/check/:date', authenticateToken, express.json(), async (req, res) => {
  try {
    const { date } = req.params;
    
    const [exceptionDay] = await query(
      'SELECT id, reason, description FROM exception_days WHERE date = ?',
      [date]
    );
    
    res.json({
      isExceptionDay: !!exceptionDay,
      exceptionDay: exceptionDay || null
    });
  } catch (error) {
    console.error('Error checking exception day:', error);
    res.status(500).json({ error: 'Failed to check exception day' });
  }
});

// Template download endpoints
// Download CSV template
app.get('/api/exception-days/template/csv', authenticateToken, async (req, res) => {
  try {
    // Only admins can download templates
    const [user] = await query('SELECT is_admin FROM users WHERE id = ?', [req.user.id]);
    if (!user || !user.is_admin) {
      return res.status(403).json({ error: 'Admin access required' });
    }

    // Create CSV content with proper format for bulk uploading
    const csvLines = [
      'Date,Reason,Description',
      '2024-12-25,Christmas Day,National holiday - no applications allowed',
      '2024-01-01,New Year Day,National holiday - no applications allowed', 
      '2024-04-14,Good Friday,Religious holiday',
      '2024-08-15,Independence Day,National holiday',
      '2024-10-02,Gandhi Jayanti,National holiday'
    ];
    
    const csvContent = csvLines.join('\n');
    
    // Set proper headers for CSV download
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="Exception_Days_Template.csv"');
    res.setHeader('Content-Length', Buffer.byteLength(csvContent, 'utf8').toString());
    res.setHeader('Cache-Control', 'no-cache');
    
    // Send the CSV content
    res.end(csvContent, 'utf8');
    
  } catch (error) {
    console.error('Error generating CSV template:', error);
    res.status(500).json({ error: 'Failed to generate CSV template: ' + error.message });
  }
});

// Download XLSX template
app.get('/api/exception-days/template/xlsx', authenticateToken, async (req, res) => {
  try {
    // Only admins can download templates
    const [user] = await query('SELECT is_admin FROM users WHERE id = ?', [req.user.id]);
    if (!user || !user.is_admin) {
      return res.status(403).json({ error: 'Admin access required' });
    }

    // Create a new workbook
    const workbook = XLSX.utils.book_new();
    
    // Define the data with proper formatting
    const templateData = [
      ['Date', 'Reason', 'Description'],
      ['2024-12-25', 'Christmas Day', 'National holiday - no applications allowed'],
      ['2024-01-01', 'New Year Day', 'National holiday - no applications allowed'],
      ['2024-04-14', 'Good Friday', 'Religious holiday'],
      ['2024-08-15', 'Independence Day', 'National holiday']
    ];
    
    // Create worksheet from data
    const worksheet = XLSX.utils.aoa_to_sheet(templateData);
    
    // Set column widths for better readability
    worksheet['!cols'] = [
      { wch: 12 },  // Date column
      { wch: 25 },  // Reason column  
      { wch: 50 }   // Description column
    ];
    
    // Style the header row (optional, but makes it look professional)
    const headerRange = XLSX.utils.decode_range(worksheet['!ref']);
    for (let col = headerRange.s.c; col <= headerRange.e.c; col++) {
      const cellAddress = XLSX.utils.encode_cell({ r: 0, c: col });
      if (!worksheet[cellAddress]) continue;
      
      // Make header bold (if supported by the XLSX library version)
      worksheet[cellAddress].s = {
        font: { bold: true },
        fill: { fgColor: { rgb: 'E6E6FA' } }
      };
    }
    
    // Add the worksheet to workbook
    XLSX.utils.book_append_sheet(workbook, worksheet, 'Exception Days Template');
    
    // Write the workbook to buffer with proper options
    const xlsxBuffer = XLSX.write(workbook, {
      type: 'buffer',
      bookType: 'xlsx',
      compression: false  // Disable compression to avoid corruption
    });
    
    // Set proper headers for Excel download
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', 'attachment; filename="Exception_Days_Template.xlsx"');
    res.setHeader('Content-Length', xlsxBuffer.length.toString());
    res.setHeader('Cache-Control', 'no-cache');
    
    // Send the buffer
    res.end(xlsxBuffer);
    
  } catch (error) {
    console.error('Error generating XLSX template:', error);
    res.status(500).json({ error: 'Failed to generate XLSX template: ' + error.message });
  }
});

// Bulk upload exception days
app.post('/api/exception-days/bulk-upload', authenticateToken, bulkUpload.single('file'), async (req, res) => {
  try {
    // Only admins can bulk upload
    const [user] = await query('SELECT is_admin FROM users WHERE id = ?', [req.user.id]);
    if (!user || !user.is_admin) {
      return res.status(403).json({ error: 'Admin access required' });
    }

    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const filePath = req.file.path;
    const fileExtension = path.extname(req.file.originalname).toLowerCase();
    
    let exceptionDaysData = [];
    
    try {
      if (fileExtension === '.csv') {
        // Parse CSV file
        const csvData = [];
        await new Promise((resolve, reject) => {
          fs.createReadStream(filePath)
            .pipe(csv())
            .on('data', (data) => csvData.push(data))
            .on('end', resolve)
            .on('error', reject);
        });
        
        exceptionDaysData = csvData.map(row => ({
          date: row.Date || row.date,
          reason: row.Reason || row.reason,
          description: row.Description || row.description || ''
        }));
        
      } else if (fileExtension === '.xlsx' || fileExtension === '.xls') {
        // Parse Excel file
        const workbook = XLSX.readFile(filePath);
        const sheetName = workbook.SheetNames[0];
        const worksheet = workbook.Sheets[sheetName];
        const jsonData = XLSX.utils.sheet_to_json(worksheet);
        
        exceptionDaysData = jsonData.map(row => ({
          date: row.Date || row.date,
          reason: row.Reason || row.reason,
          description: row.Description || row.description || ''
        }));
      } else {
        throw new Error('Unsupported file format');
      }
      
      // Validate and process data
      const results = {
        total: exceptionDaysData.length,
        created: 0,
        skipped: 0,
        errors: []
      };
      
      for (let i = 0; i < exceptionDaysData.length; i++) {
        const rowNum = i + 2; // Account for header row
        const { date, reason, description } = exceptionDaysData[i];
        
        // Validate required fields
        if (!date || !reason) {
          results.errors.push(`Row ${rowNum}: Date and Reason are required`);
          continue;
        }
        
        // Validate date format
        const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
        if (!dateRegex.test(date)) {
          results.errors.push(`Row ${rowNum}: Invalid date format. Use YYYY-MM-DD`);
          continue;
        }
        
        // Check if date already exists
        const [existingDay] = await query(
          'SELECT id FROM exception_days WHERE date = ?',
          [date]
        );
        
        if (existingDay) {
          results.skipped++;
          continue;
        }
        
        try {
          // Insert new exception day
          const id = uuidv4();
          await query(
            'INSERT INTO exception_days (id, date, reason, description) VALUES (?, ?, ?, ?)',
            [id, date, reason.trim(), description?.trim() || null]
          );
          results.created++;
        } catch (insertError) {
          results.errors.push(`Row ${rowNum}: ${insertError.message}`);
        }
      }
      
      res.json({
        message: 'Bulk upload completed',
        results
      });
      
    } catch (parseError) {
      console.error('Error parsing file:', parseError);
      res.status(400).json({ error: 'Failed to parse file: ' + parseError.message });
    } finally {
      // Clean up uploaded file
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }
    }
    
  } catch (error) {
    console.error('Error in bulk upload:', error);
    res.status(500).json({ error: 'Failed to process bulk upload' });
  }
});

// Start the server
app.listen(port, host, () => {
  console.log(`Server is running on http://${host}:${port}`);
  console.log(`Production server available at http://210.212.246.131:${port}`);
  console.log(`Server running on public IP: 210.212.246.131:${port}`);
});

