import { z } from 'zod';

export const registrationSchema = z.object({
  email: z.email(),
  password: z.string().min(3).max(32),
});

export const loginSchema = z.object({
  email: z.email(),
  password: z.string(),
});

export type RegistrationDto = z.infer<typeof registrationSchema>;
export type LoginDto = z.infer<typeof loginSchema>;

// const emailSchema = z
//   .string()
//   .email('Невірний формат email')
//   .trim()
//   .toLowerCase();

// const passwordSchema = z
//   .string()
//   .min(8, 'Пароль має бути не менше 8 символів')
//   .max(32, 'Пароль занадто довгий')
//   .regex(/[A-Z]/, 'Має містити хоча б одну велику літеру')
//   .regex(/[0-9]/, 'Має містити хоча б одну цифру');

// export const registrationSchema = z.object({
//   email: emailSchema,
//   password: passwordSchema,
//   confirmPassword: z.string(),
// }).refine((data) => data.password === data.confirmPassword, {
//   message: "Паролі не збігаються",
//   path: ["confirmPassword"],
// });

// export const loginSchema = z.object({
//   email: emailSchema,
//   password: z.string().min(1, 'Пароль обов’язковий'),
// });

// export type RegistrationDto = z.infer<typeof registrationSchema>;
// export type LoginDto = z.infer<typeof loginSchema>;
