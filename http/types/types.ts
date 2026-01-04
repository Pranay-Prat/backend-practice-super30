import { z } from "zod";
export const SignUpSchema = z.object({
  name: z.string().min(1, "Name is required"),
  email: z.email("Invalid email address"),
  password: z.string().min(6, "Password must be at least 6 charcters"),
  role: z.enum(["teacher", "student"]),
});
export const SignInSchema = z.object({
    email: z.email("Invalid email"),
    password: z.string().min(6,"Password must be at least 6 characters")  
})
export const ClassSchema = z.object({
  className:z.string()
})
export const AddStudentSchema = z.object({
  studentId: z.string()
})