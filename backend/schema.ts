import { z } from 'zod';

// Users Entity Schema
export const userSchema = z.object({
  user_id: z.string(),
  email: z.string().email(),
  password_hash: z.string(),
  is_active: z.boolean(),
  created_at: z.coerce.date(),
  updated_at: z.coerce.date().nullable()
});

// Users Input Schemas
export const createUserInputSchema = z.object({
  email: z.string().email(),
  password_hash: z.string().min(8),
  // is_active, created_at, and updated_at are automatically managed
});

export const updateUserInputSchema = z.object({
  user_id: z.string(),
  email: z.string().email().optional(),
  password_hash: z.string().min(8).optional(),
  is_active: z.boolean().optional(),
});

// Users Query Schema
export const searchUserInputSchema = z.object({
  query: z.string().optional(),
  limit: z.number().int().positive().default(10),
  offset: z.number().int().nonnegative().default(0),
  sort_by: z.enum(['email', 'created_at']).default('created_at'),
  sort_order: z.enum(['asc', 'desc']).default('desc')
});

// Calculations Entity Schema
export const calculationSchema = z.object({
  calculation_id: z.string(),
  input_value: z.string().nullable(),
  operation: z.string().nullable(),
  result: z.string().nullable(),
  created_at: z.coerce.date(),
  updated_at: z.coerce.date().nullable(),
  device_type: z.string().nullable(),
  device_id: z.string().nullable(),
  error_message: z.string().nullable(),
  user_agent: z.string().nullable()
});

// Calculations Input Schemas
export const createCalculationInputSchema = z.object({
  input_value: z.string().nullable(),
  operation: z.string().nullable(),
  result: z.string().nullable(),
  device_type: z.string().nullable(),
  device_id: z.string().nullable(),
  error_message: z.string().nullable(),
  user_agent: z.string().nullable(),
  // calculation_id, created_at are auto-generated
});

export const updateCalculationInputSchema = z.object({
  calculation_id: z.string(),
  input_value: z.string().nullable().optional(),
  operation: z.string().nullable().optional(),
  result: z.string().nullable().optional(),
  device_type: z.string().nullable().optional(),
  device_id: z.string().nullable().optional(),
  error_message: z.string().nullable().optional(),
  user_agent: z.string().nullable().optional(),
  updated_at: z.coerce.date().optional()
});

// Calculations Query Schema
export const searchCalculationInputSchema = z.object({
  query: z.string().optional(),
  limit: z.number().int().positive().default(10),
  offset: z.number().int().nonnegative().default(0),
  sort_by: z.enum(['created_at', 'operation']).default('created_at'),
  sort_order: z.enum(['asc', 'desc']).default('desc')
});

// Settings Entity Schema
export const settingSchema = z.object({
  setting_id: z.string(),
  user_id: z.string(),
  theme: z.string().nullable(),
  button_size: z.string().nullable(),
  created_at: z.coerce.date(),
  updated_at: z.coerce.date().nullable()
});

// Settings Input Schemas
export const createSettingInputSchema = z.object({
  user_id: z.string(),
  theme: z.string().nullable(),
  button_size: z.string().nullable(),
  // setting_id, created_at are auto-generated
});

export const updateSettingInputSchema = z.object({
  setting_id: z.string(),
  theme: z.string().nullable().optional(),
  button_size: z.string().nullable().optional(),
  updated_at: z.coerce.date().optional()
});

// Settings Query Schema
export const searchSettingInputSchema = z.object({
  query: z.string().optional(),
  limit: z.number().int().positive().default(10),
  offset: z.number().int().nonnegative().default(0),
  sort_by: z.enum(['created_at', 'user_id']).default('created_at'),
  sort_order: z.enum(['asc', 'desc']).default('desc')
});

// Inferred Types
export type User = z.infer<typeof userSchema>;
export type CreateUserInput = z.infer<typeof createUserInputSchema>;
export type UpdateUserInput = z.infer<typeof updateUserInputSchema>;
export type SearchUserInput = z.infer<typeof searchUserInputSchema>;

export type Calculation = z.infer<typeof calculationSchema>;
export type CreateCalculationInput = z.infer<typeof createCalculationInputSchema>;
export type UpdateCalculationInput = z.infer<typeof updateCalculationInputSchema>;
export type SearchCalculationInput = z.infer<typeof searchCalculationInputSchema>;

export type Setting = z.infer<typeof settingSchema>;
export type CreateSettingInput = z.infer<typeof createSettingInputSchema>;
export type UpdateSettingInput = z.infer<typeof updateSettingInputSchema>;
export type SearchSettingInput = z.infer<typeof searchSettingInputSchema>;