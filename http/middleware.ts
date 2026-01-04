import { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";
interface JwtPayload {
  userId: string;
  role: "teacher" | "student";
}
export interface AuthRequest extends Request {
  user?: JwtPayload;
}
export const authMiddleware = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const token = req.headers.authorization;
  if (!token) {
    res.status(401).json({
      success: false,
      error: "Unauthorized, token missing or invalid",
    });
    return;
  }
  try {
    const { userId, role } = jwt.verify(
      token,
      process.env.JWT_PASSWORD!
    ) as JwtPayload;
    req.userId = userId;
    req.role = role;
    next();
  } catch (error) {
    res.status(401).json({
      success: false,
      error: "Unauthorized, token missing or invalid",
    });
  }
};
export const teacherAuthMiddleware = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  if (!req.role || req.role != "teacher") {
    res.status(403).json({
      success: false,
      error: "Forbidden, teacher access required",
    });
    return;
  }
  next();
};
