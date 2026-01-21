import React, { createContext, useContext, useState, ReactNode, useEffect, useCallback, useMemo } from 'react';
import { BulkStudent } from '@/components/BulkAddStudentsDialog';
import { format, addDays, isBefore, parseISO, differenceInDays } from 'date-fns';
import { showError, showSuccess } from '@/utils/toast';
import apiClient from '@/utils/apiClient';

// API Client Configuration - Production Ready (Public IP Only)
const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://210.212.246.131:3009';

type Session = {
  access_token: string;
  user: any;
};

type User = {
  id: string;
  email: string;
};

// --- DATA TYPES ---
export type RequestStatus = 'Pending' | 'Approved' | 'Rejected' | 'Forwarded' | 'Cancelled' | 'Cancellation Pending' | 'Retried';
export type CertificateStatus = 'Pending Upload' | 'Pending Verification' | 'Approved' | 'Rejected' | 'Overdue';

export type Profile = {
  id: string;
  first_name: string;
  last_name: string;
  email: string;
  username?: string;
  is_admin: boolean;
  is_tutor: boolean;
  profile_photo?: string;
};

export interface Student {
  id: string;
  name: string;
  register_number: string;
  tutor_id: string;
  batch: string;
  semester: number;
  leave_taken: number;
  is_active: boolean;
  email: string;
  mobile: string;
  profile_photo?: string;
}

export interface Staff {
  id: string;
  name: string;
  email: string;
  username: string;
  mobile?: string;
  profile_photo?: string;
  is_admin: boolean;
  is_tutor: boolean;
  assigned_batch?: string;
  assigned_semester?: number;
}

export interface LeaveRequest {
  id: string;
  student_id: string;
  student_name: string;
  student_register_number: string;
  tutor_id: string;
  tutor_name: string;
  start_date: string;
  end_date: string;
  total_days: number;
  subject: string;
  description: string;
  status: RequestStatus;
  cancel_reason?: string;
  original_status?: RequestStatus;
  created_at: string;
}

export interface ODRequest {
  id: string;
  student_id: string;
  student_name: string;
  student_register_number: string;
  tutor_id: string;
  tutor_name: string;
  start_date: string;
  end_date: string;
  total_days: number;
  purpose: string;
  destination: string;
  description: string;
  status: RequestStatus;
  cancel_reason?: string;
  certificate_url?: string;
  certificate_status?: CertificateStatus;
  upload_deadline?: string;
  original_status?: RequestStatus;
  created_at: string;
}

export type ProfileChangeType = 'email' | 'mobile' | 'password';
export type ProfileChangeStatus = 'Pending' | 'Approved' | 'Rejected';

export interface ProfileChangeRequest {
  id: string;
  student_id: string;
  student_name: string;
  student_register_number: string;
  tutor_id: string;
  tutor_name: string;
  change_type: ProfileChangeType;
  current_value?: string;
  requested_value: string;
  reason?: string;
  status: ProfileChangeStatus;
  admin_comments?: string;
  requested_at: string;
  reviewed_at?: string;
  reviewed_by?: string;
  reviewer_name?: string;
}

// --- FORM DATA TYPES ---
export type NewStaffData = {
  name: string;
  email: string;
  username: string;
  password?: string;
  is_admin: boolean;
  is_tutor: boolean;
};

export type NewStudentData = {
  name: string;
  registerNumber: string;
  tutorName: string;
  batch: string;
  semester: number;
  email: string;
  mobile: string;
  password?: string;
};

// --- SESSION MANAGEMENT ---
interface SessionManager {
  lastActivity: number;
  timeoutId: NodeJS.Timeout | null;
  isActive: boolean;
  INACTIVITY_TIMEOUT: number; // 15 minutes in milliseconds
}

// --- CONTEXT DEFINITION ---
interface IAppContext {
  session: Session | null;
  user: User | null;
  profile: Profile | null;
  role: 'Admin' | 'Tutor' | 'Student' | null;
  loading: boolean;
  sessionManager: SessionManager;
  students: Student[]; // All students (including inactive) - for reports
  activeStudents: Student[]; // Only active students - for general use
  staff: Staff[];
  leaveRequests: LeaveRequest[];
  odRequests: ODRequest[];
  profileChangeRequests: ProfileChangeRequest[];
  currentUser: Student | null;
  currentTutor: Staff | null;
  handleLogin: (identifier: string, password: string) => Promise<{ error: { message: string } | null }>;
  handleLogout: () => Promise<void>;
  addStudent: (studentData: NewStudentData) => Promise<void>;
  updateStudent: (id: string, data: Partial<Student>) => Promise<void>;
  deleteStudent: (id: string) => Promise<void>;
  bulkAddStudents: (newStudents: BulkStudent[]) => Promise<void>;
  addStaff: (staffMember: NewStaffData) => Promise<void>;
  updateStaff: (id: string, data: Partial<Staff>) => Promise<void>;
  deleteStaff: (id: string) => Promise<void>;
  assignBatchToTutor: (tutorId: string, batch: string, semester: number) => Promise<void>;
  addLeaveRequest: (request: Omit<LeaveRequest, 'id' | 'status' | 'student_name' | 'student_id' | 'student_register_number' | 'tutor_id' | 'tutor_name' | 'created_at' | 'original_status'>) => Promise<void>;
  updateLeaveRequestStatus: (id: string, status: RequestStatus, reason?: string) => Promise<void>;
  requestLeaveCancellation: (id: string, reason: string) => Promise<void>;
  approveRejectLeaveCancellation: (id: string, approve: boolean) => Promise<void>;
  addODRequest: (request: Omit<ODRequest, 'id' | 'status' | 'student_name' | 'student_id' | 'student_register_number' | 'tutor_id' | 'tutor_name' | 'created_at' | 'original_status'>) => Promise<void>;
  updateODRequestStatus: (id: string, status: RequestStatus, reason?: string) => Promise<void>;
  requestODCancellation: (id: string, reason: string) => Promise<void>;
  approveRejectODCancellation: (id: string, approve: boolean) => Promise<void>;
  createProfileChangeRequest: (changeType: ProfileChangeType, currentValue: string, requestedValue: string, reason?: string) => Promise<void>;
  updateProfileChangeRequestStatus: (id: string, status: ProfileChangeStatus, adminComments?: string) => Promise<void>;
  updateTutorProfile: (id: string, data: { email?: string; mobile?: string; password?: string }) => Promise<void>;
  updateCurrentUserProfile: (data: { email?: string; mobile?: string; password?: string }) => Promise<void>;
  getTutors: () => Staff[];
  uploadODCertificate: (id: string, file: File) => Promise<void>;
  verifyODCertificate: (id: string, isApproved: boolean) => Promise<void>;
  handleOverdueCertificates: () => Promise<void>;
  uploadProfilePhoto: (file: File) => Promise<string>;
  removeProfilePhoto: () => Promise<void>;
  refreshData: () => Promise<void>;
  fetchWeeklyLeaveData: (batch?: string) => Promise<any[]>;
  fetchDailyLeaveData: (batch?: string) => Promise<any[]>;
  syncStudentStatusWithBatch: (batchId: string, isActive: boolean) => Promise<void>;
  syncStudentSemesterWithBatch: (batchId: string, semester: number) => Promise<void>;
}

const AppContext = createContext<IAppContext | undefined>(undefined);

// --- PROVIDER COMPONENT ---
export const AppProvider = ({ children }: { children: ReactNode }) => {
  const [session, setSession] = useState<Session | null>(null);
  const [user, setUser] = useState<User | null>(null);
  const [profile, setProfile] = useState<Profile | null>(null);
  const [loadingInitial, setLoadingInitial] = useState(true);
  
  // Session management state
  const [sessionManager, setSessionManager] = useState<SessionManager>({
    lastActivity: Date.now(),
    timeoutId: null,
    isActive: true,
    INACTIVITY_TIMEOUT: 15 * 60 * 1000 // 15 minutes in milliseconds
  });

  const [students, setStudents] = useState<Student[]>([]);
  const [staff, setStaff] = useState<Staff[]>([]);
  const [leaveRequests, setLeaveRequests] = useState<LeaveRequest[]>([]);
  const [odRequests, setODRequests] = useState<ODRequest[]>([]);
  const [profileChangeRequests, setProfileChangeRequests] = useState<ProfileChangeRequest[]>([]);
  
  const [currentUser, setCurrentUser] = useState<Student | null>(null);
  const [currentTutor, setCurrentTutor] = useState<Staff | null>(null);
  const [pollingInterval, setPollingInterval] = useState<NodeJS.Timeout | null>(null);
  const [lastFetchTime, setLastFetchTime] = useState<number>(0);

  const role = useMemo(() => {
    if (!profile) return null;
    if (profile.is_admin) return 'Admin';
    if (profile.is_tutor) return 'Tutor';
    return 'Student';
  }, [profile]);

  // Compute active students (for general use - excludes inactive students)
  const activeStudents = useMemo(() => {
    return students.filter(student => student.is_active);
  }, [students]);

  // Automatic data polling function
  const pollData = useCallback(async (userProfile: Profile, silent: boolean = true) => {
    try {
      const currentRole = userProfile.is_admin ? 'Admin' : userProfile.is_tutor ? 'Tutor' : 'Student';
      const now = Date.now();
      
      // Rate limiting: don't fetch more than once every 5 seconds
      if (now - lastFetchTime < 5000 && silent) {
        return;
      }
      
      setLastFetchTime(now);

      if (currentRole === 'Admin') {
        // Get all students, staff, leave requests, OD requests, and profile change requests
        const [studentsResponse, staffResponse, leaveResponse, odResponse, profileChangeResponse] = await Promise.all([
          apiClient.get('/students'),
          apiClient.get('/staff'),
          apiClient.get('/leave-requests'),
          apiClient.get('/od-requests'),
          apiClient.get('/profile-change-requests')
        ]);

        const adminRecord = staffResponse.data.find((staff: Staff) => staff.id === userProfile.id);
        if (adminRecord) setCurrentTutor(adminRecord);
        
        setStudents(studentsResponse.data || []);
        setStaff(staffResponse.data || []);
        setLeaveRequests(leaveResponse.data || []);
        setODRequests(odResponse.data || []);
        setProfileChangeRequests(profileChangeResponse.data || []);

      } else if (currentRole === 'Tutor') {
        // Get staff, students, and requests for tutor's students
        const [studentsResponse, staffResponse, leaveResponse, odResponse, profileChangeResponse] = await Promise.all([
          apiClient.get('/students'),
          apiClient.get('/staff'),
          apiClient.get('/leave-requests'),
          apiClient.get('/od-requests'),
          apiClient.get('/profile-change-requests')
        ]);

        const tutorRecord = staffResponse.data.find((staff: Staff) => staff.id === userProfile.id);
        if (tutorRecord) {
          setCurrentTutor(tutorRecord);
          
          const tutorStudents = studentsResponse.data.filter((student: Student) => student.tutor_id === tutorRecord.id);
          const studentIds = tutorStudents.map((s: Student) => s.id);
          
          setStudents(tutorStudents || []);
          setLeaveRequests(leaveResponse.data.filter((req: LeaveRequest) => studentIds.includes(req.student_id)) || []);
          setODRequests(odResponse.data.filter((req: ODRequest) => studentIds.includes(req.student_id)) || []);
          setProfileChangeRequests(profileChangeResponse.data.filter((req: ProfileChangeRequest) => studentIds.includes(req.student_id)) || []);
        }

      } else if (currentRole === 'Student') {
        // Get student data and their requests
        const [studentsResponse, staffResponse, leaveResponse, odResponse] = await Promise.all([
          apiClient.get('/students'),
          apiClient.get('/staff'),
          apiClient.get('/leave-requests'),
          apiClient.get('/od-requests')
        ]);

        const studentRecord = studentsResponse.data.find((student: Student) => student.id === userProfile.id);
        if (studentRecord) {
          setCurrentUser(studentRecord);
          
          if (studentRecord.tutor_id) {
            const tutorRecord = staffResponse.data.find((staff: Staff) => staff.id === studentRecord.tutor_id);
            if (tutorRecord) setStaff([tutorRecord]);
          }
          
          setLeaveRequests(leaveResponse.data.filter((req: LeaveRequest) => req.student_id === userProfile.id) || []);
          setODRequests(odResponse.data.filter((req: ODRequest) => req.student_id === userProfile.id) || []);
        }
      }
    } catch (error: any) {
      if (!silent) {
        showError(`Failed to refresh data: ${error.response?.data?.error || error.message}`);
      }
      console.error('Polling error:', error);
    }
  }, [lastFetchTime]); // Include lastFetchTime but ensure it doesn't cause circular updates

  // Fetch data based on user profile and role (initial load)
  const fetchDataForProfile = useCallback(async (userProfile: Profile) => {
    const currentRole = userProfile.is_admin ? 'Admin' : userProfile.is_tutor ? 'Tutor' : 'Student';

    // Reset data
    setStudents([]);
    setStaff([]);
    setLeaveRequests([]);
    setODRequests([]);
    setProfileChangeRequests([]);
    setCurrentUser(null);
    setCurrentTutor(null);

    try {
      if (currentRole === 'Admin') {
        // Get admin's staff record
        const staffResponse = await apiClient.get('/staff');
        const adminRecord = staffResponse.data.find((staff: Staff) => staff.id === userProfile.id);
        if (adminRecord) setCurrentTutor(adminRecord);

        // Get all students
        const studentsResponse = await apiClient.get('/students');
        setStudents(studentsResponse.data || []);

        // Get all staff
        setStaff(staffResponse.data || []);

        // Get all leave requests
        const leaveResponse = await apiClient.get('/leave-requests');
        setLeaveRequests(leaveResponse.data || []);

        // Get all OD requests
        const odResponse = await apiClient.get('/od-requests');
        setODRequests(odResponse.data || []);

        // Get all profile change requests
        const profileChangeResponse = await apiClient.get('/profile-change-requests');
        setProfileChangeRequests(profileChangeResponse.data || []);

      } else if (currentRole === 'Tutor') {
        // Get tutor's staff record
        const staffResponse = await apiClient.get('/staff');
        const tutorRecord = staffResponse.data.find((staff: Staff) => staff.id === userProfile.id);
        if (!tutorRecord) throw new Error("Tutor record not found");
        setCurrentTutor(tutorRecord);

        // Get students assigned to this tutor
        const studentsResponse = await apiClient.get('/students');
        const tutorStudents = studentsResponse.data.filter((student: Student) => student.tutor_id === tutorRecord.id);
        setStudents(tutorStudents || []);

        // Get leave requests for tutor's students
        const leaveResponse = await apiClient.get('/leave-requests');
        const studentIds = tutorStudents.map((s: Student) => s.id);
        const tutorLeaveRequests = leaveResponse.data.filter((req: LeaveRequest) => 
          studentIds.includes(req.student_id)
        );
        setLeaveRequests(tutorLeaveRequests || []);

        // Get OD requests for tutor's students
        const odResponse = await apiClient.get('/od-requests');
        const tutorODRequests = odResponse.data.filter((req: ODRequest) => 
          studentIds.includes(req.student_id)
        );
        setODRequests(tutorODRequests || []);

        // Get profile change requests for tutor's students
        const profileChangeResponse = await apiClient.get('/profile-change-requests');
        const tutorProfileChangeRequests = profileChangeResponse.data.filter((req: ProfileChangeRequest) => 
          studentIds.includes(req.student_id)
        );
        setProfileChangeRequests(tutorProfileChangeRequests || []);

      } else if (currentRole === 'Student') {
        console.log('Fetching student data for profile:', userProfile);
        
        // Get student record
        const studentsResponse = await apiClient.get('/students');
        console.log('Students API response:', studentsResponse.data);
        
        const studentRecord = studentsResponse.data.find((student: Student) => student.id === userProfile.id);
        console.log('Found student record:', studentRecord);
        console.log('Looking for student with ID:', userProfile.id);
        console.log('Available student IDs:', studentsResponse.data.map((s: Student) => s.id));
        
        if (!studentRecord) {
          const error = `Student record not found for ID: ${userProfile.id}`;
          console.error(error);
          showError(error);
          throw new Error(error);
        }
        
        console.log('Setting currentUser:', studentRecord);
        setCurrentUser(studentRecord);

        // Get tutor information
        if (studentRecord.tutor_id) {
          const staffResponse = await apiClient.get('/staff');
          const tutorRecord = staffResponse.data.find((staff: Staff) => staff.id === studentRecord.tutor_id);
          if (tutorRecord) {
            console.log('Found tutor record:', tutorRecord);
            setStaff([tutorRecord]);
          } else {
            console.warn('Tutor not found for ID:', studentRecord.tutor_id);
          }
        }

        // Get student's leave requests
        const leaveResponse = await apiClient.get('/leave-requests');
        const studentLeaveRequests = leaveResponse.data.filter((req: LeaveRequest) => 
          req.student_id === userProfile.id
        );
        console.log('Student leave requests:', studentLeaveRequests);
        setLeaveRequests(studentLeaveRequests || []);

        // Get student's OD requests
        const odResponse = await apiClient.get('/od-requests');
        const studentODRequests = odResponse.data.filter((req: ODRequest) => 
          req.student_id === userProfile.id
        );
        console.log('Student OD requests:', studentODRequests);
        setODRequests(studentODRequests || []);
        
        console.log('Student data fetch completed successfully');
      }
    } catch (error: any) {
      showError(`Failed to fetch data: ${error.response?.data?.error || error.message}`);
    }
  }, []);

  // Setup polling effect
  useEffect(() => {
    if (profile && session) {
      // Start polling every 10 seconds for real-time updates
      const interval = setInterval(() => {
        if (profile) { // Double-check profile exists
          pollData(profile, true); // Silent polling
        }
      }, 10000); // 10 seconds
      
      setPollingInterval(interval);
      
      // Also poll when the user focuses on the window
      const handleFocus = () => {
        if (profile) { // Double-check profile exists
          pollData(profile, true);
        }
      };
      
      window.addEventListener('focus', handleFocus);
      
      return () => {
        clearInterval(interval);
        window.removeEventListener('focus', handleFocus);
      };
    } else {
      // Clear polling when logged out
      if (pollingInterval) {
        clearInterval(pollingInterval);
        setPollingInterval(null);
      }
    }
  }, [profile, session]); // Only depend on profile and session, not pollData

  useEffect(() => {
    const initializeSessionAndData = async () => {
      // Check for existing session in localStorage
      const token = localStorage.getItem('auth_token');
      
      if (token) {
        try {
          // Get user profile from backend
          const profileResponse = await apiClient.get('/profile');
          const userProfile = profileResponse.data;
          
          // Create session and user objects
          const currentSession = {
            access_token: token,
            user: { id: userProfile.id, email: userProfile.email }
          };
          
          setSession(currentSession);
          setUser(currentSession.user);
          setProfile(userProfile);
          
          // Fetch data based on the profile
          await fetchDataForProfile(userProfile);
        } catch (error: any) {
          // Token is invalid, clear it
          localStorage.removeItem('auth_token');
          localStorage.removeItem('user_profile');
          setSession(null);
          setUser(null);
          setProfile(null);
        }
      } else {
        setSession(null);
        setUser(null);
        setProfile(null);
      }
      
      setLoadingInitial(false);
    };

    initializeSessionAndData();
  }, [fetchDataForProfile]);

  // Utility function to upload profile photo
  const uploadProfilePhoto = async (file: File): Promise<string> => {
    const formData = new FormData();
    formData.append('profilePhoto', file);
    
    try {
      const response = await apiClient.post('/upload/profile-photo', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });
      
      // Refresh profile data after successful upload
      try {
        const profileResponse = await apiClient.get('/profile');
        const updatedProfile = profileResponse.data;
        setProfile(updatedProfile);
        
        // Update the current user or tutor data
        const updatedRole = updatedProfile.is_admin ? 'Admin' : updatedProfile.is_tutor ? 'Tutor' : 'Student';
        if (updatedRole === 'Student' && currentUser) {
          setCurrentUser(prev => prev ? { ...prev, profile_photo: updatedProfile.profile_photo } : null);
        } else if ((updatedRole === 'Admin' || updatedRole === 'Tutor') && currentTutor) {
          setCurrentTutor(prev => prev ? { ...prev, profile_photo: updatedProfile.profile_photo } : null);
        }
        
        // Use silent polling to refresh other data
        await pollData(updatedProfile, true);
      } catch (profileError) {
        console.error('Failed to refresh profile after upload:', profileError);
      }
      
      return response.data.path;
    } catch (error: any) {
      throw new Error(error.response?.data?.error || 'Failed to upload photo');
    }
  };

  // Utility function to remove profile photo
  const removeProfilePhoto = async (): Promise<void> => {
    try {
      await apiClient.delete('/upload/profile-photo');
      
      // Get updated profile from backend to reflect the change
      try {
        const profileResponse = await apiClient.get('/profile');
        const updatedProfile = profileResponse.data;
        setProfile(updatedProfile);
        
        // Manually update currentUser or currentTutor to reflect the new profile photo immediately
        const updatedRole = updatedProfile.is_admin ? 'Admin' : updatedProfile.is_tutor ? 'Tutor' : 'Student';
        if (updatedRole === 'Student' && currentUser) {
          setCurrentUser(prev => prev ? { ...prev, profile_photo: updatedProfile.profile_photo } : null);
        } else if ((updatedRole === 'Admin' || updatedRole === 'Tutor') && currentTutor) {
          setCurrentTutor(prev => prev ? { ...prev, profile_photo: updatedProfile.profile_photo } : null);
        }

        // Use silent polling to refresh data without clearing existing data
        await pollData(updatedProfile, true);
      } catch (profileError) {
        console.error('Failed to refresh profile after removal:', profileError);
        // Still try to refresh with current profile if available
        if (profile) {
          await pollData(profile, true);
        }
      }
    } catch (error: any) {
      throw new Error(error.response?.data?.error || 'Failed to remove profile photo');
    }
  };

  const handleLogin = async (identifier: string, password: string) => {
    try {
      const response = await apiClient.post('/auth/login', { identifier, password });
      if (response.data.token) {
        // Store token and user profile in local storage
        localStorage.setItem('auth_token', response.data.token);
        localStorage.setItem('user_profile', JSON.stringify(response.data.user));

        // Get full profile from backend
        const profileResponse = await apiClient.get('/profile');
        const userProfile = profileResponse.data;

        // Set session and user objects
        setSession({ access_token: response.data.token, user: response.data.user });
        setUser(response.data.user);
        setProfile(userProfile);

        // Fetch profile-specific data
        await fetchDataForProfile(userProfile);

        return { error: null };
      } else {
        return { error: { message: "Login failed: No token received" } };
      }
    } catch (error: any) {
      console.error('Login failed:', error);
      const errorMessage = error.response?.data?.error || error.response?.data?.message || error.message || "Invalid username or password.";
      return { error: errorMessage };
    }
  };
  
  const handleLogout = async () => {
    try {
      await apiClient.post('/auth/logout');
      localStorage.removeItem('auth_token');
      localStorage.removeItem('user_profile');
      setSession(null);
      setUser(null);
      setProfile(null);
      setStudents([]);
      setStaff([]);
      setLeaveRequests([]);
      setODRequests([]);
      setProfileChangeRequests([]);
      setCurrentUser(null);
      setCurrentTutor(null);
      showSuccess('Logged out successfully!');
    } catch (error: any) {
      showError(`Failed to logout: ${error.response?.data?.error || error.message}`);
    }
  };


  const addStudent = async (studentData: NewStudentData) => {
    if (!studentData.password) {
      showError("Password is required for new students.");
      return;
    }
    const tutor = staff.find(s => s.name === studentData.tutorName);
    if (!tutor) {
      showError(`Tutor '${studentData.tutorName}' not found.`);
      return;
    }

    try {
      const payload = {
        email: studentData.email,
        password: studentData.password,
        name: studentData.name,
        registerNumber: studentData.registerNumber,
        tutorId: tutor.id,
        batch: studentData.batch,
        semester: studentData.semester,
        mobile: studentData.mobile,
      };

      console.log('Adding student with payload:', payload);
      const response = await apiClient.post('/students', payload);
      console.log('Add student API response:', response.data);
      showSuccess('Student added successfully!');
      
      // Refresh data
      if (profile) await fetchDataForProfile(profile);
    } catch (error: any) {
      console.error('Failed to add student - Full error object:', error);
      console.error('Error response:', error.response);
      console.error('Error response data:', error.response?.data);
      console.error('Error status:', error.response?.status);
      const errorMessage = error.response?.data?.error || error.response?.data?.message || error.message || 'Unknown error';
      showError(`Failed to add student: ${errorMessage}`);
      throw error;
    }
  };

  const updateStudent = async (id: string, data: Partial<Student>) => {
    try {
      console.log('Updating student with ID:', id);
      console.log('Update payload:', data);
      const response = await apiClient.put(`/students/${id}`, data);
      console.log('Update student API response:', response.data);
      showSuccess('Student updated!');
      setStudents(prev => prev.map(s => s.id === id ? response.data : s));
      if (currentUser?.id === id) {
        setCurrentUser(response.data);
      }
    } catch (error: any) {
      console.error('Failed to update student - Full error object:', error);
      console.error('Error response:', error.response);
      console.error('Error response data:', error.response?.data);
      console.error('Error status:', error.response?.status);
      const errorMessage = error.response?.data?.error || error.response?.data?.message || error.message || 'Unknown error';
      showError(`Failed to update student: ${errorMessage}`);
      throw error;
    }
  };

  const deleteStudent = async (id: string) => {
    try {
      await apiClient.delete(`/students/${id}`);
      showSuccess('Student removed!');
      setStudents(prev => prev.filter(s => s.id !== id));
    } catch (error: any) {
      showError(`Failed to delete student: ${error.response?.data?.error || error.message}`);
    }
  };

  const bulkAddStudents = async (newStudents: BulkStudent[]) => {
    console.log('Starting bulk add process with students:', newStudents);
    console.log('Current staff list:', staff);
    console.log('Current students list:', students);
    
    setLoadingInitial(true);
    let successCount = 0;
    const errors: string[] = [];
    const detailedErrors: any[] = [];

    try {
      // Validate input
      if (!newStudents || newStudents.length === 0) {
        throw new Error('No students provided for bulk add');
      }

      if (!staff || staff.length === 0) {
        throw new Error('No staff members found. Please ensure staff data is loaded.');
      }

      console.log('Processing', newStudents.length, 'students...');

      for (let i = 0; i < newStudents.length; i++) {
        const student = newStudents[i];
        console.log(`Processing student ${i + 1}/${newStudents.length}:`, student);

        try {
          // Validate required fields
          if (!student.name || !student.email || !student.mobile || !student.password || !student.registerNumber || !student.tutorName || !student.batch || !student.semester) {
            const missingFields = [];
            if (!student.name) missingFields.push('name');
            if (!student.email) missingFields.push('email');
            if (!student.mobile) missingFields.push('mobile');
            if (!student.password) missingFields.push('password');
            if (!student.registerNumber) missingFields.push('registerNumber');
            if (!student.tutorName) missingFields.push('tutorName');
            if (!student.batch) missingFields.push('batch');
            if (!student.semester) missingFields.push('semester');
            
            const error = `Student ${student.name || 'Unknown'}: Missing required fields: ${missingFields.join(', ')}`;
            errors.push(error);
            detailedErrors.push({ student, error: 'Missing fields', details: missingFields });
            continue;
          }

          // Find tutor
          const tutor = staff.find(s => s.name === student.tutorName);
          if (!tutor) {
            const availableTutors = staff.filter(s => s.is_tutor).map(s => s.name);
            const error = `Student ${student.name}: Tutor '${student.tutorName}' not found. Available tutors: ${availableTutors.join(', ')}`;
            errors.push(error);
            detailedErrors.push({ student, error: 'Tutor not found', details: { requestedTutor: student.tutorName, availableTutors } });
            continue;
          }

          // Check for duplicate email/register number
          const existingByEmail = students.find(existing => existing.email === student.email);
          const existingByRegNum = students.find(existing => existing.register_number === student.registerNumber);
          
          if (existingByEmail) {
            const error = `Student ${student.name}: Email '${student.email}' already exists (used by ${existingByEmail.name})`;
            errors.push(error);
            detailedErrors.push({ student, error: 'Duplicate email', details: { existingStudent: existingByEmail } });
            continue;
          }
          
          if (existingByRegNum) {
            const error = `Student ${student.name}: Register Number '${student.registerNumber}' already exists (used by ${existingByRegNum.name})`;
            errors.push(error);
            detailedErrors.push({ student, error: 'Duplicate register number', details: { existingStudent: existingByRegNum } });
            continue;
          }

          // Prepare payload
          const payload = {
            email: student.email,
            password: student.password,
            name: student.name,
            registerNumber: student.registerNumber,
            tutorId: tutor.id,
            batch: student.batch,
            semester: student.semester,
            mobile: student.mobile,
          };

          console.log('Sending payload for student', student.name, ':', payload);

          // Make API call
          const response = await apiClient.post('/students', payload);
          console.log('Successfully created student', student.name, ':', response.data);
          successCount++;
          
        } catch (studentError: any) {
          console.error(`Error processing student ${student.name}:`, studentError);
          const errorMessage = studentError.response?.data?.error || studentError.message || 'Unknown error';
          errors.push(`Student ${student.name}: ${errorMessage}`);
          detailedErrors.push({ 
            student, 
            error: 'API call failed', 
            details: { 
              message: errorMessage, 
              status: studentError.response?.status,
              data: studentError.response?.data 
            } 
          });
        }
      }

      // Final reporting
      console.log('Bulk add completed. Success:', successCount, 'Errors:', errors.length);
      console.log('Detailed errors:', detailedErrors);

      if (errors.length > 0) {
        const errorSummary = `Bulk add completed with ${errors.length} errors and ${successCount} successful additions.`;
        showError(errorSummary);
        console.error('Bulk add error details:', {
          summary: errorSummary,
          errors: errors,
          detailedErrors: detailedErrors
        });
      } else {
        showSuccess(`Successfully added all ${successCount} students!`);
      }
      
      // Refresh data
      if (profile) {
        console.log('Refreshing data after bulk add...');
        await fetchDataForProfile(profile);
      }
      
    } catch (generalError: any) {
      console.error('General error in bulk add process:', generalError);
      showError(`Bulk add failed: ${generalError.message || 'Unknown error'}`);
    } finally {
      setLoadingInitial(false);
    }
  };

  const addStaff = async (staffMember: NewStaffData) => {
    if (!staffMember.password) {
      showError("Password is required for new staff members.");
      return;
    }

    try {
      await apiClient.post('/staff', {
        email: staffMember.email,
        password: staffMember.password,
        name: staffMember.name,
        username: staffMember.username,
        isAdmin: staffMember.is_admin,
        isTutor: staffMember.is_tutor
      });

      showSuccess("Staff member added successfully!");
      if (profile) await fetchDataForProfile(profile);
    } catch (error: any) {
      showError(`Failed to create staff: ${error.response?.data?.error || error.message}`);
    }
  };
  
  const updateStaff = async (id: string, data: Partial<Staff>) => {
    try {
      const response = await apiClient.put(`/staff/${id}`, data);
      showSuccess("Staff member updated successfully!");
      setStaff(prev => prev.map(s => s.id === id ? response.data : s));
    } catch (error: any) {
      showError(`Failed to update staff: ${error.response?.data?.error || error.message}`);
    }
  };

  const deleteStaff = async (id: string) => {
    try {
      await apiClient.delete(`/staff/${id}`);
      showSuccess("Staff member removed!");
      setStaff(prev => prev.filter(s => s.id !== id));
    } catch (error: any) {
      showError(`Failed to delete staff: ${error.response?.data?.error || error.message}`);
    }
  };

  const addLeaveRequest = async (request: Omit<LeaveRequest, 'id' | 'status' | 'student_name' | 'student_id' | 'student_register_number' | 'tutor_id' | 'tutor_name' | 'created_at' | 'original_status'>) => {
    if (!currentUser) { 
      const err = "Current user not found. Cannot submit request.";
      showError(err);
      throw new Error(err);
    }
    const tutor = staff.find(s => s.id === currentUser.tutor_id);
    if (!tutor) {
      const err = "Tutor details not found. Cannot submit request.";
      showError(err);
      throw new Error(err);
    }

    try {
      const payload = {
        startDate: request.start_date,
        endDate: request.end_date,
        totalDays: request.total_days,
        subject: request.subject,
        description: request.description
      };

      const response = await apiClient.post('/leave-requests', payload);
      setLeaveRequests(prev => [...prev, response.data]);
      showSuccess('Leave request submitted successfully!');
    } catch (error: any) {
      showError(`Failed to submit leave request: ${error.response?.data?.error || error.message}`);
      throw error;
    }
  };

  const updateLeaveRequestStatus = async (id: string, status: RequestStatus, reason?: string) => {
    try {
      const response = await apiClient.put(`/leave-requests/${id}/status`, { status, cancelReason: reason });
      showSuccess("Status updated!");
      setLeaveRequests(prev => prev.map(req => req.id === id ? response.data : req));
      
      // Refresh student data to update leave counts and charts
      if (profile) {
        await fetchDataForProfile(profile);
      }
    } catch (error: any) {
      showError(`Failed to update status: ${error.response?.data?.error || error.message}`);
      throw error; // Re-throw so UI can handle the error
    }
  };

  const requestLeaveCancellation = async (id: string, reason: string, cancelData?: any) => {
    try {
      const data: any = {
        status: 'Cancellation Pending', 
        cancelReason: reason 
      };

      // If partial cancellation data is provided, add it to the request
      if (cancelData?.isPartial) {
        data.startDate = cancelData.startDate;
        data.endDate = cancelData.endDate;
        data.isPartial = true;
      }

      const response = await apiClient.put(`/leave-requests/${id}/status`, data);
      showSuccess('Cancellation request sent!');

      if (cancelData?.isPartial) {
        const partialDays = differenceInDays(new Date(cancelData.endDate), new Date(cancelData.startDate)) + 1;

        setLeaveRequests(prev => prev.map(req => {
          if (req.id === id) {
            return { 
              ...response.data, 
              total_days: req.total_days - partialDays
            };
          }
          return req;
        }));
      } else {
        setLeaveRequests(prev => prev.map(req => req.id === id ? response.data : req));
      }
    } catch (error: any) {
      showError(`Failed to request cancellation: ${error.response?.data?.error || error.message}`);
    }
  };

  const approveRejectLeaveCancellation = async (id: string, approve: boolean) => {
    try {
      const status = approve ? 'Cancelled' : 'Pending';
      const response = await apiClient.put(`/leave-requests/${id}/status`, { status });
      showSuccess(`Leave cancellation ${approve ? 'approved' : 'rejected'}!`);
      setLeaveRequests(prev => prev.map(req => req.id === id ? response.data : req));
    } catch (error: any) {
      showError(`Failed to process cancellation: ${error.response?.data?.error || error.message}`);
      throw error; // Re-throw so UI can handle the error
    }
  };

  const addODRequest = async (request: Omit<ODRequest, 'id' | 'status' | 'student_name' | 'student_id' | 'student_register_number' | 'tutor_id' | 'tutor_name' | 'created_at' | 'original_status'>) => {
    if (!currentUser) { 
      const err = "Current user not found. Cannot submit request.";
      showError(err);
      throw new Error(err);
    }
    const tutor = staff.find(s => s.id === currentUser.tutor_id);
    if (!tutor) {
      const err = "Tutor details not found. Cannot submit request.";
      showError(err);
      throw new Error(err);
    }

    try {
      const payload = {
        startDate: request.start_date,
        endDate: request.end_date,
        totalDays: request.total_days,
        purpose: request.purpose,
        destination: request.destination,
        description: request.description
      };

      const response = await apiClient.post('/od-requests', payload);
      setODRequests(prev => [...prev, response.data]);
      showSuccess('OD request submitted successfully!');
    } catch (error: any) {
      showError(`Failed to submit OD request: ${error.response?.data?.error || error.message}`);
      throw error;
    }
  };

  const updateODRequestStatus = async (id: string, status: RequestStatus, reason?: string) => {
    try {
      const response = await apiClient.put(`/od-requests/${id}/status`, { status, cancelReason: reason });
      showSuccess("Status updated!");
      setODRequests(prev => prev.map(req => req.id === id ? response.data : req));
      
      // Refresh student data to update leave counts and charts
      if (profile) {
        await fetchDataForProfile(profile);
      }
    } catch (error: any) {
      showError(`Failed to update status: ${error.response?.data?.error || error.message}`);
      throw error; // Re-throw so UI can handle the error
    }
  };

  const requestODCancellation = async (id: string, reason: string) => {
    try {
      const response = await apiClient.put(`/od-requests/${id}/status`, { 
        status: 'Cancellation Pending', 
        cancelReason: reason 
      });
      showSuccess('Cancellation request sent!');
      setODRequests(prev => prev.map(req => req.id === id ? response.data : req));
    } catch (error: any) {
      showError(`Failed to request cancellation: ${error.response?.data?.error || error.message}`);
    }
  };

  const approveRejectODCancellation = async (id: string, approve: boolean) => {
    try {
      const status = approve ? 'Cancelled' : 'Pending';
      const response = await apiClient.put(`/od-requests/${id}/status`, { status });
      showSuccess(`OD cancellation ${approve ? 'approved' : 'rejected'}!`);
      setODRequests(prev => prev.map(req => req.id === id ? response.data : req));
    } catch (error: any) {
      showError(`Failed to process cancellation: ${error.response?.data?.error || error.message}`);
      throw error; // Re-throw so UI can handle the error
    }
  };

  const uploadODCertificate = async (id: string, file: File) => {
    console.log('=== Certificate Upload Started ===');
    console.log('OD Request ID:', id);
    console.log('File details:', {
      name: file.name,
      size: file.size,
      type: file.type,
      lastModified: file.lastModified
    });
    
    // Validate file
    if (!file) {
      throw new Error('No file provided');
    }
    
    // Check file size (10MB limit)
    const maxSize = 10 * 1024 * 1024; // 10MB
    if (file.size > maxSize) {
      throw new Error('File size must be less than 10MB');
    }
    
    // Check file type
    const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'application/pdf'];
    if (!allowedTypes.includes(file.type)) {
      throw new Error('File must be an image (JPEG, PNG, GIF) or PDF');
    }
    
    const formData = new FormData();
    formData.append('certificate', file);
    
    console.log('FormData created with certificate field');
    console.log('FormData entries:');
    for (const [key, value] of formData.entries()) {
      console.log(`${key}:`, value instanceof File ? `File: ${value.name}` : value);
    }
    
    try {
      console.log('Sending POST request to:', `/api/od-requests/${id}/certificate`);
      
      // Use fetch instead of axios for better multipart handling
      const token = localStorage.getItem('auth_token');
      if (!token) {
        throw new Error('No authentication token found');
      }
      
      const response = await fetch(`${API_BASE_URL}/api/od-requests/${id}/certificate/upload`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          // Don't set Content-Type - let browser set it with boundary
        },
        body: formData
      });
      
      console.log('Response status:', response.status);
      console.log('Response ok:', response.ok);
      
      if (!response.ok) {
        const errorData = await response.json();
        console.error('Upload failed:', errorData);
        throw new Error(errorData.error || `HTTP ${response.status}`);
      }
      
      const responseData = await response.json();
      console.log('Upload successful:', responseData);
      
      showSuccess(responseData.message || 'Certificate uploaded successfully!');
      
      // Force immediate refresh of all data to ensure admin interface shows changes
      console.log('Forcing immediate data refresh after certificate upload...');
      if (profile) {
        await pollData(profile, false); // Non-silent refresh to ensure immediate update
      }
      
      // Update the OD request with the returned data (fallback)
      if (responseData.id) {
        // The response contains the full updated request object
        console.log('Updating OD request with response data:', responseData);
        setODRequests(prev => prev.map(req => 
          req.id === id ? responseData : req
        ));
      } else {
        console.log('No request data in response, refreshing OD requests');
        // Fallback: refresh all OD requests
        try {
          const odResponse = await apiClient.get('/od-requests');
          const updatedRequest = odResponse.data.find((req: any) => req.id === id);
          if (updatedRequest) {
            console.log('Found updated request:', updatedRequest);
            setODRequests(prev => prev.map(req => req.id === id ? updatedRequest : req));
          }
        } catch (refreshError) {
          console.error('Failed to refresh OD requests:', refreshError);
        }
      }
      
      return responseData;
      
    } catch (error: any) {
      console.error('Certificate upload error:', error);
      
      let errorMessage = 'Failed to upload certificate';
      if (error.message) {
        errorMessage = error.message;
      }
      
      showError(errorMessage);
      throw error;
    }
  };

  const verifyODCertificate = async (id: string, isApproved: boolean) => {
    try {
      const response = await apiClient.put(`/od-requests/${id}/certificate/verify`, { 
        isApproved,
        certificateStatus: isApproved ? 'Approved' : 'Rejected'
      });
      showSuccess(`Certificate ${isApproved ? 'approved' : 'rejected'}!`);
      
      // Force immediate refresh to ensure all users see the verification change
      console.log('Forcing immediate data refresh after certificate verification...');
      if (profile) {
        await pollData(profile, false); // Non-silent refresh to ensure immediate update
      }
      
      setODRequests(prev => prev.map(req => req.id === id ? response.data : req));
    } catch (error: any) {
      showError(`Failed to verify certificate: ${error.response?.data?.error || error.message}`);
      throw error;
    }
  };

  const handleOverdueCertificates = useCallback(async () => {
    try {
      const response = await apiClient.put('/od-requests/handle-overdue-certificates');
      const overdueCount = response.data.overdueCount || 0;
      if (overdueCount > 0) {
        showSuccess(`${overdueCount} overdue certificates have been marked as overdue.`);
        // Refresh OD requests to show updated status
        if (profile) await fetchDataForProfile(profile);
      }
    } catch (error: any) {
      showError(`Failed to handle overdue certificates: ${error.response?.data?.error || error.message}`);
    }
  }, [profile, fetchDataForProfile]);

  const createProfileChangeRequest = async (changeType: ProfileChangeType, currentValue: string, requestedValue: string, reason?: string) => {
    if (!profile) {
      const err = "Current profile not found. Cannot submit profile change request.";
      showError(err);
      throw new Error(err);
    }

    let approverId, approverName;
    const isStudent = !profile.is_admin && !profile.is_tutor;
    
    if (isStudent) {
      const tutor = staff.find(s => s.id === currentUser?.tutor_id);
      if (!tutor) {
        const err = "Tutor details not found. Cannot submit profile change request.";
        showError(err);
        throw new Error(err);
      }
      approverId = tutor.id;
      approverName = tutor.name;
    } else {
      const admin = staff.find(s => s.is_admin);
      if (!admin) {
        const err = "Admin not found. Cannot submit profile change request.";
        showError(err);
        throw new Error(err);
      }
      approverId = admin.id;
      approverName = admin.name;
    }

    try {
      const payload = {
        student_id: isStudent ? currentUser?.id : undefined,
        student_name: isStudent ? currentUser?.name : undefined,
        tutor_id: approverId,
        tutor_name: approverName,
        change_type: changeType,
        current_value: currentValue,
        requested_value: requestedValue,
        reason,
        status: 'Pending',
        requested_at: new Date().toISOString()
      };

      const response = await apiClient.post('/profile-change-requests', payload);
      setProfileChangeRequests(prev => [...prev, response.data]);
      showSuccess('Profile change request submitted successfully!');
    } catch (error: any) {
      showError(`Failed to submit profile change request: ${error.response?.data?.error || error.message}`);
      throw error;
    }
  };

  const updateProfileChangeRequestStatus = async (id: string, status: ProfileChangeStatus, adminComments?: string) => {
    try {
      const response = await apiClient.put(`/profile-change-requests/${id}/status`, { 
        status, 
        adminComments 
      });
      showSuccess(`Profile change request ${status.toLowerCase()}!`);
      setProfileChangeRequests(prev => prev.map(req => req.id === id ? response.data : req));
      
      // If approved, refresh student data to reflect the changes
      if (status === 'Approved' && profile) {
        await fetchDataForProfile(profile);
      }
    } catch (error: any) {
      showError(`Failed to update profile change request status: ${error.response?.data?.error || error.message}`);
    }
  };

  const updateTutorProfile = async (id: string, data: { email?: string; mobile?: string; password?: string }) => {
    try {
      const response = await apiClient.put(`/staff/${id}/profile`, data);
      showSuccess('Profile updated successfully!');
      
      // Update staff list with new data
      setStaff(prev => prev.map(s => s.id === id ? { ...s, ...response.data } : s));
      
      // Update currentTutor if it's the current user's profile
      if (currentTutor?.id === id) {
        setCurrentTutor(prev => prev ? { ...prev, ...response.data } : null);
      }
      
      // If updating current user's profile, also update the profile state
      if (profile?.id === id) {
        const profileResponse = await apiClient.get('/profile');
        setProfile(profileResponse.data);
      }
      
      // Force a complete data refresh to ensure changes are visible to all users (especially admins)
      if (profile) {
        await pollData(profile, false); // Use pollData instead of fetchDataForProfile to avoid circular dependency
      }
    } catch (error: any) {
      showError(`Failed to update profile: ${error.response?.data?.error || error.message}`);
      throw error;
    }
  };

  const updateCurrentUserProfile = async (data: { email?: string; mobile?: string; password?: string }) => {
    if (!profile) {
      const err = "Current profile not found. Cannot update profile.";
      showError(err);
      throw new Error(err);
    }

    try {
      // Determine if current user is a staff member or student
      const isStaff = profile.is_admin || profile.is_tutor;
      
      if (isStaff) {
        // Update staff profile
        await updateTutorProfile(profile.id, data);
      } else {
        // For students, we should still use the direct update (not request approval)
        // This is a design decision - if students should also go through approval,
        // this should use createProfileChangeRequest instead
        const response = await apiClient.put(`/students/${profile.id}/profile`, data);
        showSuccess('Profile updated successfully!');
        
        // Update student in students list
        setStudents(prev => prev.map(s => s.id === profile.id ? { ...s, ...response.data } : s));
        
        // Update currentUser if it exists
        if (currentUser?.id === profile.id) {
          setCurrentUser(prev => prev ? { ...prev, ...response.data } : null);
        }
        
        // Update profile state
        const profileResponse = await apiClient.get('/profile');
        setProfile(profileResponse.data);
        
        // Force a complete data refresh to ensure changes are visible to all users (especially admins)
        if (profile) {
          await pollData(profile, false); // Use pollData instead of fetchDataForProfile to avoid circular dependency
        }
      }
    } catch (error: any) {
      showError(`Failed to update profile: ${error.response?.data?.error || error.message}`);
      throw error;
    }
  };

  const getTutors = () => staff.filter(s => s.is_tutor);

  const assignBatchToTutor = async (tutorId: string, batch: string, semester: number) => {
    try {
      // Update tutor's assigned batch and semester
      await updateStaff(tutorId, {
        assigned_batch: batch,
        assigned_semester: semester,
      });

      // Get all students in this batch and semester and assign them to this tutor
      const studentsToAssign = students.filter(
        (student) => student.batch === batch && student.semester === semester
      );

      // Update each student's tutor_id
      for (const student of studentsToAssign) {
        await updateStudent(student.id, {
          tutor_id: tutorId,
        });
      }

      showSuccess(`Successfully assigned batch ${batch} semester ${semester} to tutor with ${studentsToAssign.length} students!`);
      
      // Refresh data to reflect the changes
      if (profile) {
        await fetchDataForProfile(profile);
      }
    } catch (error: any) {
      showError(`Failed to assign batch to tutor: ${error.response?.data?.error || error.message}`);
      throw error;
    }
  };

  // Chart data fetching functions
  const fetchWeeklyLeaveData = async (batch?: string): Promise<any[]> => {
    try {
      const params = batch ? { batch } : {};
      const response = await apiClient.get('/api/leave-data/weekly', { params });
      return response.data || [];
    } catch (error: any) {
      console.error('Failed to fetch weekly leave data:', error);
      showError(`Failed to fetch weekly leave data: ${error.response?.data?.error || error.message}`);
      return [];
    }
  };

  const fetchDailyLeaveData = async (batch?: string): Promise<any[]> => {
    try {
      const params = batch ? { batch } : {};
      const response = await apiClient.get('/api/leave-data/daily', { params });
      return response.data || [];
    } catch (error: any) {
      console.error('Failed to fetch daily leave data:', error);
      showError(`Failed to fetch daily leave data: ${error.response?.data?.error || error.message}`);
      return [];
    }
  };

  // Function to sync student status with batch status
  const syncStudentStatusWithBatch = async (batchId: string, isActive: boolean) => {
    try {
      const response = await apiClient.put(`/students/sync-batch-status/${batchId}`, { isActive });
      
      if (response.data.updatedCount > 0) {
        console.log(`✅ Updated ${response.data.updatedCount} students to ${isActive ? 'active' : 'inactive'} status for batch ${batchId}`);
        
        // Refresh student data to reflect the changes
        if (profile) {
          await fetchDataForProfile(profile);
        }
        
        return { success: true, updatedCount: response.data.updatedCount };
      } else {
        console.log(`ℹ️ No students found to update for batch ${batchId}`);
        return { success: true, updatedCount: 0 };
      }
    } catch (error: any) {
      console.warn(`⚠️ Failed to sync student status for batch ${batchId}:`, error.response?.data?.error || error.message);
      // Don't throw error or show error toast - this is handled by the calling function
      return { success: false, error: error.response?.data?.error || error.message };
    }
  };

  const syncStudentSemesterWithBatch = async (batchId: string, semester: number) => {
    try {
      const response = await apiClient.put(`/students/sync-batch-semester/${batchId}`, { semester });
      
      if (response.data.updatedCount > 0) {
        showSuccess(`Updated ${response.data.updatedCount} students to semester ${semester} for batch ${batchId}`);
        
        // Refresh student data to reflect the changes
        if (profile) {
          await fetchDataForProfile(profile);
        }
      } else {
        showSuccess(`No students needed updating for batch ${batchId}`);
      }
    } catch (error: any) {
      console.error(`Failed to sync student semester for batch ${batchId}:`, error);
      showError(`Failed to sync student semester: ${error.response?.data?.error || error.message}`);
      throw error;
    }
  };

  // Manual refresh function for user-triggered updates
  const refreshData = useCallback(async () => {
    if (profile) {
      await pollData(profile, false); // Non-silent refresh
      showSuccess('Data refreshed successfully!');
    }
  }, [profile, pollData]);

  // Session Management Functions
  const resetInactivityTimer = useCallback(() => {
    console.log('Resetting inactivity timer');
    
    setSessionManager(prev => {
      // Clear existing timeout
      if (prev.timeoutId) {
        clearTimeout(prev.timeoutId);
      }
      
      // Set new timeout for 15 minutes
      const timeoutId = setTimeout(async () => {
        console.log('Session expired due to inactivity');
        showError('Session expired due to inactivity. Please log in again.');
          try {
            await apiClient.post('/auth/logout');
            localStorage.removeItem('auth_token');
            localStorage.removeItem('user_profile');
            setSession(null);
            setUser(null);
            setProfile(null);
            setStudents([]);
            setStaff([]);
            setLeaveRequests([]);
            setODRequests([]);
            setProfileChangeRequests([]);
            setCurrentUser(null);
            setCurrentTutor(null);
            showSuccess('Logged out successfully due to inactivity!');
          } catch (error) {
            console.error('Logout API call failed:', error);
            // Clear local storage anyway
            localStorage.removeItem('auth_token');
            localStorage.removeItem('user_profile');
            window.location.reload();
          }
      }, prev.INACTIVITY_TIMEOUT);
      
      return {
        ...prev,
        lastActivity: Date.now(),
        timeoutId: timeoutId,
        isActive: true
      };
    });
  }, []); // Remove handleLogout dependency to prevent infinite loop

  const updateActivity = useCallback(() => {
    setSessionManager(prev => {
      const now = Date.now();
      const timeSinceLastActivity = now - prev.lastActivity;
      
      // Only reset timer if more than 5 seconds has passed (to avoid excessive timer resets)
      if (timeSinceLastActivity > 5000) {
        // Clear existing timeout and reset it
        if (prev.timeoutId) {
          clearTimeout(prev.timeoutId);
        }
        
        const timeoutId = setTimeout(async () => {
          console.log('Session expired due to inactivity');
          showError('Session expired due to inactivity. Please log in again.');
          try {
            await apiClient.post('/auth/logout');
            localStorage.removeItem('auth_token');
            localStorage.removeItem('user_profile');
            setSession(null);
            setUser(null);
            setProfile(null);
            setStudents([]);
            setStaff([]);
            setLeaveRequests([]);
            setODRequests([]);
            setProfileChangeRequests([]);
            setCurrentUser(null);
            setCurrentTutor(null);
            showSuccess('Logged out successfully due to inactivity!');
          } catch (error) {
            console.error('Logout API call failed:', error);
            // Clear local storage anyway
            localStorage.removeItem('auth_token');
            localStorage.removeItem('user_profile');
            window.location.reload();
          }
        }, prev.INACTIVITY_TIMEOUT);
        
        return {
          ...prev,
          lastActivity: now,
          timeoutId: timeoutId,
          isActive: true
        };
      }
      
      return prev; // No change needed
    });
  }, []); // Remove handleLogout dependency to prevent infinite loop

  // Session management effects
  useEffect(() => {
    if (!session) {
      // Clear timeout when logged out
      if (sessionManager.timeoutId) {
        clearTimeout(sessionManager.timeoutId);
        setSessionManager(prev => ({ ...prev, timeoutId: null, isActive: false }));
      }
      return;
    }

    // Start session timeout when logged in
    resetInactivityTimer();

    // Activity detection events
    const events = ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart', 'click'];
    
    events.forEach(event => {
      document.addEventListener(event, updateActivity, { passive: true });
    });

    // Page visibility change detection
    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
        console.log('Page became visible, updating activity');
        updateActivity();
      }
    };
    
    document.addEventListener('visibilitychange', handleVisibilityChange);

    // Note: Removed beforeunload handler to prevent logout on page refresh
    // Session will persist across page reloads and be handled by the inactivity timer

    // Cleanup function
    return () => {
      events.forEach(event => {
        document.removeEventListener(event, updateActivity);
      });
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      
      if (sessionManager.timeoutId) {
        clearTimeout(sessionManager.timeoutId);
      }
    };
  }, [session]); // Only depend on session to prevent infinite loop

  // Auto-logout on tab close or browser close
  useEffect(() => {
    const handleUnload = () => {
      if (session) {
        // Clear local session data
        localStorage.removeItem('auth_token');
        localStorage.removeItem('user_profile');
      }
    };

    window.addEventListener('unload', handleUnload);
    return () => window.removeEventListener('unload', handleUnload);
  }, [session]);

  const value = {
    session, user, profile, role, loading: loadingInitial, sessionManager,
    students, activeStudents, staff, leaveRequests, odRequests, profileChangeRequests, currentUser, currentTutor,
    handleLogin, handleLogout,
    addStudent, updateStudent, deleteStudent, bulkAddStudents,
    addStaff, updateStaff, deleteStaff, assignBatchToTutor,
    addLeaveRequest, updateLeaveRequestStatus, requestLeaveCancellation, approveRejectLeaveCancellation,
    addODRequest, updateODRequestStatus, requestODCancellation, approveRejectODCancellation,
    createProfileChangeRequest, updateProfileChangeRequestStatus,
    updateTutorProfile, updateCurrentUserProfile,
    getTutors, uploadODCertificate, verifyODCertificate, handleOverdueCertificates,
    uploadProfilePhoto, removeProfilePhoto,
    refreshData, fetchWeeklyLeaveData, fetchDailyLeaveData, syncStudentStatusWithBatch, syncStudentSemesterWithBatch,
  };

  return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
};

export const useAppContext = () => {
  const context = useContext(AppContext);
  if (context === undefined) {
    throw new Error('useAppContext must be used within an AppProvider');
  }
  return context;
};

