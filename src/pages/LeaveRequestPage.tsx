import React, { useEffect, useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import * as z from 'zod';
import { differenceInCalendarDays, format } from 'date-fns';
import { Link } from 'react-router-dom';

import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { DatePicker } from '@/components/ui/datepicker';
import { showSuccess, showError } from '@/utils/toast';
import Layout from '@/components/Layout';
import { useAppContext } from '@/context/AppContext';
import { useBatchContext } from '@/context/BatchContext';
import apiClient from '@/utils/apiClient';

const leaveRequestSchema = z.object({
  startDate: z.date({
    required_error: "A start date is required.",
  }),
  endDate: z.date({
    required_error: "An end date is required.",
  }),
  durationType: z.enum(['full_day', 'half_day_forenoon', 'half_day_afternoon'], {
    required_error: "Please select a leave duration type.",
  }),
  subject: z.string().min(5, "Subject must be at least 5 characters long.").max(100, "Subject must be 100 characters or less."),
  description: z.string().min(10, "Description must be at least 10 characters long.").max(500, "Description must be 500 characters or less."),
}).refine((data) => data.endDate >= data.startDate, {
  message: "End date cannot be before start date.",
  path: ["endDate"],
}).refine((data) => {
  if (data.startDate && data.endDate) {
    const days = differenceInCalendarDays(data.endDate, data.startDate) + 1;
    return days <= 10;
  }
  return true;
}, {
  message: "Leave duration cannot exceed 10 days.",
  path: ["endDate"],
});

type LeaveRequestFormValues = z.infer<typeof leaveRequestSchema>;

const LeaveRequestPage = () => {
  const { addLeaveRequest, currentUser } = useAppContext();
  const { getCurrentActiveSemester, isDateWithinSemester, getSemesterDateRange } = useBatchContext();
  const [totalDays, setTotalDays] = useState(0);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [currentSemester, setCurrentSemester] = useState<number | null>(null);
  const [exceptionDays, setExceptionDays] = useState<string[]>([]);

  if (!currentUser?.is_active) {
    return (
      <Layout>
        <div className="flex items-center justify-center h-full">
          <p className="text-lg text-red-600">Inactivated accounts cannot make leave requests.</p>
        </div>
      </Layout>
    );
  }

  const form = useForm<LeaveRequestFormValues>({
    resolver: zodResolver(leaveRequestSchema),
    defaultValues: {
      durationType: 'full_day',
      subject: '',
      description: '',
    }
  });

  const startDate = form.watch('startDate');
  const endDate = form.watch('endDate');
  const durationType = form.watch('durationType');

  // Get current semester when user profile loads
  useEffect(() => {
    if (currentUser?.batch) {
      const activeSemester = getCurrentActiveSemester(currentUser.batch);
      setCurrentSemester(activeSemester);
    }
  }, [currentUser, getCurrentActiveSemester]);

  // Fetch exception days on component mount
  useEffect(() => {
    const fetchExceptionDays = async () => {
      try {
        const response = await apiClient.get('/api/exception-days/public');
        console.log('Raw exception days response:', response.data);
        
        // Convert exception days to array of date strings for easier checking
        // The correct field name is 'date', not 'exception_date'
        const exceptionDatesArray = response.data.map((day: any) => {
          // Ensure date is in YYYY-MM-DD format
          const dateStr = day.date ? format(new Date(day.date), 'yyyy-MM-dd') : null;
          console.log('Processing exception day:', { original: day.date, formatted: dateStr });
          return dateStr;
        }).filter(date => date !== null);
        
        setExceptionDays(exceptionDatesArray);
        console.log('Final exception days array:', exceptionDatesArray);
      } catch (error: any) {
        console.error('Failed to fetch exception days:', error);
        // Set empty array on error to prevent issues
        // Backend validation will still prevent submission on exception days
        setExceptionDays([]);
      }
    };

    fetchExceptionDays();
  }, []);

  useEffect(() => {
    if (startDate && endDate && endDate >= startDate) {
      // Calculate total calendar days first
      let days = differenceInCalendarDays(endDate, startDate) + 1;
      
      // Subtract Sundays (weekends) from the count
      let currentDate = new Date(startDate);
      let sundayCount = 0;
      
      for (let i = 0; i < days; i++) {
        if (currentDate.getDay() === 0) { // Sunday = 0
          sundayCount++;
        }
        currentDate.setDate(currentDate.getDate() + 1);
      }
      
      // Working days = total days - sundays
      const workingDays = days - sundayCount;
      
      // Apply duration type calculation
      if (durationType === 'half_day_forenoon' || durationType === 'half_day_afternoon') {
        // Half-day calculation: working days * 0.5
        const halfDayTotal = workingDays * 0.5;
        setTotalDays(halfDayTotal);
      } else {
        // Full day calculation: use working days as-is
        setTotalDays(workingDays);
      }
    } else {
      setTotalDays(0);
    }
  }, [startDate, endDate, durationType]);

  const onSubmit = async (data: LeaveRequestFormValues) => {
    setIsSubmitting(true);
    
    // Only perform client-side exception day check if we have exception days data
    if (exceptionDays.length > 0) {
      // Check if any of the selected dates are exception days
      const startDateStr = format(data.startDate, 'yyyy-MM-dd');
      const endDateStr = format(data.endDate, 'yyyy-MM-dd');
      
      // Generate array of all dates in the range
      const dateRange = [];
      let currentDate = new Date(data.startDate);
      const endDate = new Date(data.endDate);
      
      while (currentDate <= endDate) {
        dateRange.push(format(currentDate, 'yyyy-MM-dd'));
        currentDate.setDate(currentDate.getDate() + 1);
      }
      
      // Check if any date in range is an exception day
      const conflictingDates = dateRange.filter(date => exceptionDays.includes(date));
      
      if (conflictingDates.length > 0) {
        showError(`Cannot apply for leave on the following exception days: ${conflictingDates.join(', ')}. Please select different dates.`);
        setIsSubmitting(false);
        return;
      }
    }
    // If we don't have exception days data, the backend will validate and return appropriate errors

    const requestData = {
      subject: data.subject,
      description: data.description,
      start_date: format(data.startDate, 'yyyy-MM-dd'),
      end_date: format(data.endDate, 'yyyy-MM-dd'),
      total_days: totalDays,
      duration_type: data.durationType,
    };
    try {
      await addLeaveRequest(requestData as any);
      showSuccess('Leave request submitted successfully!');
      form.reset();
      setTotalDays(0);
    } catch (error) {
      console.error("Failed to submit leave request:", error);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <Layout>
      <Card className="w-full max-w-4xl mx-auto transition-all duration-300 hover:shadow-xl">
        <CardHeader>
          <CardTitle className="text-2xl md:text-3xl font-bold">Leave Request Form</CardTitle>
          <CardDescription>Fill out the form below to request time off.</CardDescription>
        </CardHeader>
        <CardContent>
          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <FormField
                  control={form.control}
                  name="startDate"
                  render={({ field }) => (
                    <FormItem className="flex flex-col">
                      <FormLabel>Start Date</FormLabel>
                      <DatePicker
                        key={`start-date-${exceptionDays.length}`}
                        date={field.value}
                        setDate={field.onChange}
                        disabled={(date) => {
                          const today = new Date();
                          today.setHours(0, 0, 0, 0);
                          
                          // Disable past dates
                          if (date < today) return true;
                          
                          // Check if date is an exception day
                          const dateStr = format(date, 'yyyy-MM-dd');
                          const isExceptionDay = exceptionDays.includes(dateStr);
                          console.log('Date picker check:', { date: dateStr, isException: isExceptionDay, exceptionDays });
                          
                          if (isExceptionDay) return true;
                          
                          return false;
                        }}
                      />
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <FormField
                  control={form.control}
                  name="endDate"
                  render={({ field }) => (
                    <FormItem className="flex flex-col">
                      <FormLabel>End Date</FormLabel>
                      <DatePicker
                        key={`end-date-${exceptionDays.length}`}
                        date={field.value}
                        setDate={field.onChange}
                        disabled={(date) => {
                          const today = new Date();
                          today.setHours(0, 0, 0, 0);
                          
                          // Disable dates before start date or before today
                          const minDate = startDate || today;
                          if (date < minDate) return true;
                          
                          // Check if date is an exception day
                          const dateStr = format(date, 'yyyy-MM-dd');
                          const isExceptionDay = exceptionDays.includes(dateStr);
                          console.log('End date picker check:', { date: dateStr, isException: isExceptionDay, exceptionDays });
                          
                          if (isExceptionDay) return true;
                          
                          return false;
                        }}
                      />
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </div>

              <FormField
                control={form.control}
                name="durationType"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Leave Duration Type</FormLabel>
                    <Select onValueChange={field.onChange} defaultValue={field.value}>
                      <FormControl>
                        <SelectTrigger>
                          <SelectValue placeholder="Select leave duration type" />
                        </SelectTrigger>
                      </FormControl>
                      <SelectContent>
                        <SelectItem value="full_day">Full Day</SelectItem>
                        <SelectItem value="half_day_forenoon">Half Day (Forenoon)</SelectItem>
                        <SelectItem value="half_day_afternoon">Half Day (Afternoon)</SelectItem>
                      </SelectContent>
                    </Select>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <div className="space-y-2">
                <FormLabel htmlFor="totalDays">Total Number of Days</FormLabel>
                <Input
                  id="totalDays"
                  type="text"
                  value={totalDays % 1 === 0 ? totalDays.toString() : totalDays.toFixed(1)}
                  readOnly
                  className="bg-gray-100 dark:bg-black text-black dark:text-white cursor-not-allowed"
                />
                <p className="text-sm text-muted-foreground">
                  {durationType === 'half_day_forenoon' && 'Half day leave (Forenoon: 9:00 AM to 1:00 PM)'}
                  {durationType === 'half_day_afternoon' && 'Half day leave (Afternoon: 1:00 PM to 5:00 PM)'}
                  {durationType === 'full_day' && 'Full day leave (9:00 AM to 5:00 PM)'}
                </p>
              </div>

              <FormField
                control={form.control}
                name="subject"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Subject</FormLabel>
                    <FormControl>
                      <Input placeholder="e.g., Family Vacation" {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="description"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Description</FormLabel>
                    <FormControl>
                      <Textarea
                        placeholder="Please provide a brief reason for your leave."
                        className="resize-none"
                        rows={4}
                        {...field}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <div className="flex flex-col sm:flex-row justify-end gap-2 pt-4">
                <Button variant="outline" type="button" asChild>
                  <Link to="/dashboard">Cancel</Link>
                </Button>
                <Button type="submit" disabled={isSubmitting}>
                  {isSubmitting ? 'Submitting...' : 'Submit Request'}
                </Button>
              </div>
            </form>
          </Form>
        </CardContent>
      </Card>
    </Layout>
  );
};

export default LeaveRequestPage;
