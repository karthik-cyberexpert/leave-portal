import React, { useState, useMemo } from 'react';
import { useBatchContext, SemesterDates } from '@/context/BatchContext';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { DatePicker } from '@/components/ui/datepicker';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { useAppContext } from '@/context/AppContext';
import { addDays, isAfter, isSameDay } from 'date-fns';
import { showSuccess, showError } from '@/utils/toast';
import { Plus, Settings, Trash2, ChevronDown, ChevronRight } from 'lucide-react';

interface Semester {
  id: string;
  batch: string;
  semester: number;
  startDate: Date | undefined;
  endDate: Date | undefined;
}

export const BatchManagement = () => {
  const { students, syncStudentStatusWithBatch, syncStudentSemesterWithBatch } = useAppContext();
  const { semesterDates, setSemesterDates, saveSemesterDates, batches, createBatch, updateBatch, deleteBatch } = useBatchContext();
  
  // Debug: Log batch data whenever it changes
  React.useEffect(() => {
    console.log('🔍 BatchManagement Debug Info:');
    console.log('  - Batches array:', batches);
    console.log('  - Batches length:', batches.length);
    console.log('  - Semester dates:', semesterDates);
    console.log('  - Auth token exists:', !!localStorage.getItem('auth_token'));
  }, [batches, semesterDates]);
  const [selectedSemesters, setSelectedSemesters] = useState<Record<string, number>>({});
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false);
  const [isEditDialogOpen, setIsEditDialogOpen] = useState(false);
  const [newBatchYear, setNewBatchYear] = useState<string>('');
  const [editingBatch, setEditingBatch] = useState<{ id: string; name: string } | null>(null);
  const [expandedBatches, setExpandedBatches] = useState<Record<string, boolean>>({});

  // Function to determine current semester based on batch start year and current date
  const getCurrentSemesterForBatch = (batchStartYear: number): number => {
    const now = new Date();
    const currentYear = now.getFullYear();
    const currentMonth = now.getMonth() + 1; // getMonth() returns 0-11, so add 1 for 1-12
    
    const yearDiff = currentYear - batchStartYear;
    
    // Determine if we're in the first half (Jan-May) or second half (Jun-Dec) of academic year
    const isFirstHalf = currentMonth >= 1 && currentMonth <= 5;
    const isSecondHalf = currentMonth >= 6 && currentMonth <= 12;
    
    let semester = 1;
    
    if (yearDiff === 0) {
      // Same year as batch start
      if (isSecondHalf) {
        semester = 1; // June-December of starting year = Semester 1
      } else {
        // January-May of starting year - batch hasn't started yet
        return 0; // Invalid semester
      }
    } else if (yearDiff === 1) {
      if (isFirstHalf) {
        semester = 2; // January-May of year 2 = Semester 2
      } else {
        semester = 3; // June-December of year 2 = Semester 3
      }
    } else if (yearDiff === 2) {
      if (isFirstHalf) {
        semester = 4; // January-May of year 3 = Semester 4
      } else {
        semester = 5; // June-December of year 3 = Semester 5
      }
    } else if (yearDiff === 3) {
      if (isFirstHalf) {
        semester = 6; // January-May of year 4 = Semester 6
      } else {
        semester = 7; // June-December of year 4 = Semester 7
      }
    } else if (yearDiff === 4) {
      if (isFirstHalf) {
        semester = 8; // January-May of year 5 = Semester 8
      } else {
        // June-December of year 5 - batch has completed
        return 0; // Invalid semester
      }
    } else {
      // Beyond 4 years or before batch start
      return 0; // Invalid semester
    }
    
    return semester;
  };

  // Get batches that are eligible for semester date management (current semester only)
  const batchData = useMemo(() => {
    return batches.filter(b => {
      if (!b.is_active) return false;
      
      const currentSemester = getCurrentSemesterForBatch(b.start_year);
      // Only show batches that have a valid current semester (1-8)
      return currentSemester >= 1 && currentSemester <= 8;
    }).map(batch => {
      const currentSemester = getCurrentSemesterForBatch(batch.start_year);
      return {
        batch: batch.id,
        semesters: [currentSemester], // Only allow managing the current semester
        currentSemester
      };
    });
  }, [batches]);

  const handleSemesterChange = (batch: string, semester: number) => {
    setSelectedSemesters(prev => ({ ...prev, [batch]: semester }));
  };

  const handleDateChange = async (batch: string, semester: number, date: Date | undefined, type: 'start' | 'end') => {
    console.log('handleDateChange called:', { batch, semester, date, type });
    
    // Immediately update state with the new date
    const newSemesterDates = semesterDates.slice(); // Create a copy
    const existingIndex = newSemesterDates.findIndex(s => s.batch === batch && s.semester === semester);
    
    if (existingIndex >= 0) {
      // Update existing entry
      newSemesterDates[existingIndex] = {
        ...newSemesterDates[existingIndex],
        [type === 'start' ? 'startDate' : 'endDate']: date
      };
      console.log('Updated existing semester date entry:', { batch, semester, type, date });
    } else {
      // Create new entry
      const newEntry = {
        id: `${batch}-${semester}`,
        batch,
        semester,
        startDate: type === 'start' ? date : undefined,
        endDate: type === 'end' ? date : undefined
      };
      newSemesterDates.push(newEntry);
      console.log('Adding new semester date entry:', newEntry);
    }
    
    // Update state immediately
    setSemesterDates(newSemesterDates);
    console.log('New semester dates state:', newSemesterDates);
    
    // Auto-save with better error handling
    try {
      console.log('Auto-saving semester dates...');
      // Use the updated data directly instead of relying on state
      const dataToSave = JSON.stringify(newSemesterDates, (key, value) => {
        if (value instanceof Date) {
          return value.toISOString();
        }
        return value;
      });
      localStorage.setItem('batchSemesterDates', dataToSave);
      console.log('Semester dates auto-saved successfully to localStorage');
      showSuccess('Semester date saved successfully');
    } catch (error) {
      console.error('Auto-save failed:', error);
      showError('Failed to save semester date');
    }
  };

  // Function to get valid date range for a batch and semester
  const getValidDateRange = (batchId: string, semester: number) => {
    const batch = batches.find(b => b.id === batchId);
    if (!batch) return { minDate: new Date(), maxDate: new Date() };

    const batchStartYear = batch.start_year;
    
    // Calculate which academic year this semester falls in
    const semesterIndex = Math.floor((semester - 1) / 2);
    const semesterYear = batchStartYear + semesterIndex;
    
    let minDate: Date;
    let maxDate: Date;
    
    if (semester % 2 === 1) {
      // Odd semesters (1, 3, 5, 7): May 1st to February 28/29 (next year)
      minDate = new Date(semesterYear, 4, 1); // May 1st
      maxDate = new Date(semesterYear + 1, 1, 28); // February 28th next year (will auto-adjust for leap years)
    } else {
      // Even semesters (2, 4, 6, 8): December 1st to July 31st (next year)
      minDate = new Date(semesterYear, 11, 1); // December 1st
      maxDate = new Date(semesterYear + 1, 6, 31); // July 31st next year
    }
    
    return { minDate, maxDate };
  };

  // Function to check if a date should be disabled
  const isDateDisabled = (date: Date, batchId: string, semester: number, type: 'start' | 'end') => {
    const { minDate, maxDate } = getValidDateRange(batchId, semester);
    
    // Disable dates outside the semester's valid range
    if (date < minDate || date > maxDate) {
      return true;
    }
    
    // For end dates, ensure they're not before the start date
    if (type === 'end') {
      const semesterData = semesterDates.find(s => s.batch === batchId && s.semester === semester);
      if (semesterData?.startDate && date < semesterData.startDate) {
        return true;
      }
    }
    
    // For start dates, ensure they're not after the end date
    if (type === 'start') {
      const semesterData = semesterDates.find(s => s.batch === batchId && s.semester === semester);
      if (semesterData?.endDate && date > semesterData.endDate) {
        return true;
      }
    }
    
    return false;
  };

  // Function to determine the current active semester for a batch based on dates
  const getCurrentActiveSemester = (batch: string, semesterNumbers: number[]): number => {
    const today = new Date();
    today.setHours(0, 0, 0, 0); // Set to start of day for accurate comparison
    
    // Find the highest semester that has ended (current date is after end date)
    let activeSemester = 1; // Default to semester 1
    
    for (const semester of semesterNumbers.sort((a, b) => a - b)) {
      const semesterData = semesterDates.find(s => s.batch === batch && s.semester === semester);
      
      if (semesterData?.startDate && semesterData?.endDate) {
        const endDate = new Date(semesterData.endDate);
        endDate.setHours(0, 0, 0, 0);
        const dayAfterEnd = addDays(endDate, 1);
        
        // If today is the day after the semester ended or later, and there's a next semester
        if ((isSameDay(today, dayAfterEnd) || isAfter(today, dayAfterEnd)) && semester < 8) {
          activeSemester = semester + 1;
        }
      }
    }
    
    // Ensure we don't exceed semester 8
    return Math.min(activeSemester, 8);
  };

  const isSemesterLocked = (batch: string, semester: number) => {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    // Semester 1 is never locked
    if (semester === 1) return false;
    
    // For semester 2 and beyond, check if the previous semester has ended
    const prevSemester = semesterDates.find(s => s.batch === batch && s.semester === semester - 1);
    
    // If previous semester doesn't exist or has no end date, lock the current semester
    if (!prevSemester || !prevSemester.endDate) return true;
    
    const prevEndDate = new Date(prevSemester.endDate);
    prevEndDate.setHours(0, 0, 0, 0);
    const dayAfterPrevEnd = addDays(prevEndDate, 1);
    
    // Unlock if today is the day after the previous semester ended or later
    return isAfter(dayAfterPrevEnd, today);
  };

  const handleSave = async () => {
    try {
      await saveSemesterDates();
      showSuccess('Semester dates saved successfully!');
    } catch (error) {
      console.error('Error saving semester dates:', error);
      showError('Failed to save semester dates. Please try again.');
    }
  };

  const handleCreateBatch = async () => {
    if (!newBatchYear) {
      showError('Please enter a valid batch year.');
      return;
    }
    
    const year = parseInt(newBatchYear);
    if (isNaN(year) || year < 2000 || year > 2050) {
      showError('Please enter a valid year between 2000 and 2050.');
      return;
    }
    
    // Check if batch already exists in the local state
    if (batches.some(b => b.start_year === year)) {
      showError('A batch with this start year already exists.');
      return;
    }
    
    try {
      await createBatch(year);
      setNewBatchYear('');
      setIsCreateDialogOpen(false);
      showSuccess(`Batch ${year}-${year + 4} created successfully!`);
    } catch (error: any) {
      console.error('Error creating batch:', error);
      
      let errorMessage = 'Failed to create batch. Please try again.';
      
      // Handle specific error cases
      if (error.response?.status === 409) {
        errorMessage = `Batch ${year}-${year + 4} already exists in the database.`;
      } else if (error.response?.status === 401) {
        errorMessage = 'Authentication expired. Please log in again.';
        // Redirect to login
        setTimeout(() => {
          localStorage.removeItem('auth_token');
          localStorage.removeItem('user_profile');
          window.location.href = '/login';
        }, 2000);
      } else if (error.response?.status === 403) {
        errorMessage = 'You do not have permission to create batches.';
      } else if (error.response?.data?.error) {
        errorMessage = error.response.data.error;
      } else if (error.message) {
        errorMessage = error.message;
      }
      
      showError(errorMessage);
    }
  };
  
  const handleEditBatch = (batch: { id: string; name: string }) => {
    setEditingBatch(batch);
    setIsEditDialogOpen(true);
  };
  
  const handleUpdateBatch = async () => {
    if (!editingBatch) return;
    
    // Check authentication first
    const authToken = localStorage.getItem('auth_token');
    if (!authToken) {
      showError('Authentication required. Please log in again.');
      // Redirect to login or refresh
      window.location.href = '/login';
      return;
    }
    
    const currentBatch = batches.find(b => b.id === editingBatch.id);
    if (!currentBatch) {
      showError('Batch not found. Please refresh and try again.');
      return;
    }

    const newActiveStatus = !currentBatch.is_active;
    let batchUpdateSuccess = false;
    let studentSyncSuccess = false;
    
    try {
      console.log(`Attempting to ${newActiveStatus ? 'activate' : 'deactivate'} batch ${editingBatch.name}`);
      
      // First, update the batch
      await updateBatch(editingBatch.id, { is_active: newActiveStatus });
      batchUpdateSuccess = true;
      console.log(`✅ Batch ${editingBatch.name} status updated to ${newActiveStatus ? 'active' : 'inactive'}`);
      
      // Then, try to sync student status (this is optional and should not fail the entire operation)
      try {
        if (syncStudentStatusWithBatch) {
          await syncStudentStatusWithBatch(editingBatch.id, newActiveStatus);
          studentSyncSuccess = true;
          console.log('✅ Student status sync completed');
        }
      } catch (syncError) {
        console.warn('⚠️ Student sync failed, but batch update succeeded:', syncError);
        // Don't throw here - batch update was successful
      }
      
      // Show success message based on what succeeded
      if (batchUpdateSuccess && studentSyncSuccess) {
        showSuccess(`Batch ${editingBatch.name} updated and student statuses synchronized successfully!`);
      } else if (batchUpdateSuccess) {
        showSuccess(`Batch ${editingBatch.name} updated successfully! (Student sync will be handled automatically)`);
      }
      
      setIsEditDialogOpen(false);
      setEditingBatch(null);
    } catch (error: any) {
      console.error('❌ Error updating batch:', error);
      
      let errorMessage = 'Unknown error occurred';
      
      if (error.message) {
        errorMessage = error.message;
      } else if (error.response?.data?.error) {
        errorMessage = error.response.data.error;
      } else if (error.response?.statusText) {
        errorMessage = `${error.response.status}: ${error.response.statusText}`;
      }
      
      // Handle specific error types
      if (error.message?.includes('Authentication') || error.response?.status === 401) {
        showError('Session expired. Please log in again.');
        // Clear auth and redirect
        localStorage.removeItem('auth_token');
        localStorage.removeItem('user_profile');
        setTimeout(() => window.location.href = '/login', 2000);
      } else if (error.message?.includes('permission') || error.response?.status === 403) {
        showError('You do not have permission to perform this action.');
      } else {
        showError(`Failed to update batch: ${errorMessage}`);
      }
    }
  };
  
  const handleDeleteBatch = async (batchId: string, batchName: string) => {
    if (confirm(`Are you sure you want to delete batch ${batchName}? This action cannot be undone.`)) {
      try {
        await deleteBatch(batchId);
        showSuccess(`Batch ${batchName} deleted successfully!`);
      } catch (error: any) {
        console.error('Error deleting batch:', error);
        
        let errorMessage = 'Failed to delete batch. Please try again.';
        
        if (error.message) {
          errorMessage = error.message;
        } else if (error.response?.data?.details) {
          errorMessage = error.response.data.details;
        } else if (error.response?.data?.error) {
          errorMessage = error.response.data.error;
        }
        
        // Handle authentication errors
        if (error.message?.includes('Authentication') || error.response?.status === 401) {
          showError('Session expired. Please log in again.');
          // Clear auth and redirect
          setTimeout(() => {
            localStorage.removeItem('auth_token');
            localStorage.removeItem('user_profile');
            window.location.href = '/login';
          }, 2000);
        } else {
          showError(errorMessage);
        }
      }
    }
  };

  return (
    <Card className="shadow-sm border-gray-200">
      <CardHeader className="pb-3">
        <div className="flex justify-between items-center">
          <CardTitle className="text-xl">Batch Management</CardTitle>
          <Dialog open={isCreateDialogOpen} onOpenChange={setIsCreateDialogOpen}>
            <DialogTrigger asChild>
              <Button size="sm" className="flex items-center gap-2">
                <Plus size={16} />
                New Batch
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Create New Batch</DialogTitle>
              </DialogHeader>
              <div className="space-y-4">
                <div>
                  <Label htmlFor="batchYear">Starting Year</Label>
                  <Input
                    id="batchYear"
                    type="number"
                    placeholder="e.g., 2024"
                    value={newBatchYear}
                    onChange={(e) => setNewBatchYear(e.target.value)}
                    min="2000"
                    max="2050"
                  />
                </div>
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setIsCreateDialogOpen(false)}>
                  Cancel
                </Button>
                <Button onClick={handleCreateBatch}>
                  Create
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>

          {/* Edit Batch Dialog */}
          <Dialog open={isEditDialogOpen} onOpenChange={setIsEditDialogOpen}>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Edit Batch Settings</DialogTitle>
              </DialogHeader>
              {editingBatch && (
                <div className="space-y-4">
                  <div>
                    <Label>Batch</Label>
                    <Input value={editingBatch.name} disabled className="bg-gray-50" />
                  </div>
                  <div>
                    <Label>Current Status</Label>
                    <div className="mt-2">
                      <Badge variant={batches.find(b => b.id === editingBatch.id)?.is_active ? "default" : "secondary"}>
                        {batches.find(b => b.id === editingBatch.id)?.is_active ? 'Active' : 'Inactive'}
                      </Badge>
                    </div>
                  </div>
                </div>
              )}
              <DialogFooter>
                <Button variant="outline" onClick={() => setIsEditDialogOpen(false)}>
                  Cancel
                </Button>
                <Button onClick={handleUpdateBatch}>
                  {editingBatch && batches.find(b => b.id === editingBatch.id)?.is_active ? 'Deactivate' : 'Activate'}
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>
      </CardHeader>
      <CardContent>
        {/* Batch List Section */}
        <div className="mb-8">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Batch Period</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {batches.map((batch) => (
                  <TableRow key={batch.id}>
                    <TableCell>
                      <div>
                        <div className="font-medium">{batch.name}</div>
                        <div className="text-sm text-gray-500">{batch.start_year} - {batch.end_year}</div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant={batch.is_active ? "default" : "secondary"}>
                        {batch.is_active ? 'Active' : 'Inactive'}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex gap-1 justify-end">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleEditBatch({ id: batch.id, name: batch.name })}
                        >
                          <Settings size={16} />
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleDeleteBatch(batch.id, batch.name)}
                          className="text-red-600 hover:text-red-700 hover:bg-red-50"
                        >
                          <Trash2 size={16} />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
                {batches.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={3} className="text-center py-8 text-gray-500">
                      No batches found. Create your first batch to get started.
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </div>
        </div>

        {/* Semester Management Section */}
        <div>
          <h3 className="text-lg font-semibold mb-4">Semester Date Management</h3>
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Batch</TableHead>
                  <TableHead>Semester</TableHead>
                  <TableHead>Start Date</TableHead>
                  <TableHead>End Date</TableHead>
                  <TableHead className="text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {batchData.map(({ batch, semesters: semesterNumbers, currentSemester }) => {
                  const isLocked = false; // Current semester is never locked
                  const batchObj = batches.find(b => b.id === batch);
                  const currentDate = new Date();
                  const currentMonth = currentDate.getMonth() + 1;
                  const yearDiff = currentDate.getFullYear() - (batchObj?.start_year || 0);
                  
                  // Create a description of the current semester period
                  const startDate = semesterDates.find(s => s.batch === batch && s.semester === currentSemester)?.startDate;
                  const endDate = semesterDates.find(s => s.batch === batch && s.semester === currentSemester)?.endDate;
                  const startDateStr = startDate ? startDate.toLocaleDateString() : 'N/A';
                  const endDateStr = endDate ? endDate.toLocaleDateString() : 'N/A';
                  const semesterPeriod = `${startDateStr} - ${endDateStr}`;

                  return (
                    <TableRow key={batch}>
                      <TableCell className="font-medium">{`${batch}-${parseInt(batch) + 4}`}</TableCell>
                      <TableCell>
                        <div className="flex flex-col">
                          <span className="font-medium text-blue-600">Semester {currentSemester}</span>
                          <span className="text-xs text-gray-500">{semesterPeriod}</span>
                        </div>
                      </TableCell>
                      <TableCell>
                          <DatePicker
                            date={semesterDates.find(s => s.batch === batch && s.semester === currentSemester)?.startDate}
                            setDate={(date) => handleDateChange(batch, currentSemester, date, 'start')}
                            disabled={(date) => isDateDisabled(date, batch, currentSemester, 'start')}
                            fullDisabled={isLocked}
                          />
                      </TableCell>
                      <TableCell>
                          <DatePicker
                            date={semesterDates.find(s => s.batch === batch && s.semester === currentSemester)?.endDate}
                            setDate={(date) => handleDateChange(batch, currentSemester, date, 'end')}
                            disabled={(date) => isDateDisabled(date, batch, currentSemester, 'end')}
                            fullDisabled={isLocked}
                          />
                      </TableCell>
                      <TableCell className="text-right">
                        <Button 
                          variant="outline" 
                          size="sm"
                          onClick={() => syncStudentSemesterWithBatch(batch, currentSemester)}
                          title="Update all students in this batch to their current semester"
                        >
                          Sync Students
                        </Button>
                      </TableCell>
                    </TableRow>
                  );
                })}
                {batchData.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={5} className="text-center py-8 text-gray-500">
                      <div className="space-y-2">
                        <div>No batches are currently in an active semester period.</div>
                        <div className="text-xs text-gray-400">
                          Only batches with an active semester (based on current date and batch timeline) can have semester dates managed.
                          <br />Current date: {new Date().toLocaleDateString()} (July 2025 = various semester periods for different batches)
                        </div>
                      </div>
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </div>
        </div>
        <div className="flex justify-end mt-4">
          <Button onClick={handleSave}>Save Changes</Button>
        </div>
      </CardContent>
    </Card>
  );
};

