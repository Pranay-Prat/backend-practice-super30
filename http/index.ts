import express from "express";
import {
  AddStudentSchema,
  ClassSchema,
  SignInSchema,
  SignUpSchema,
} from "./types/types";
import { ClassModel, UserModel } from "./model/models";
import { compare, hash } from "bcryptjs";
import jwt from "jsonwebtoken";
import { authMiddleware, teacherAuthMiddleware } from "./middleware";
import mongoose from "mongoose";

const app = express();
app.use(express.json());

app.post("/auth/signup", async (req, res) => {
  const { success, data } = SignUpSchema.safeParse(req.body);
  if (!success) {
    res.json({
      success: false,
      error: "Invalid request schema",
    });
    return;
  }
  const isUser = await UserModel.findOne({
    email: data.email,
  });
  if (isUser) {
    res.status(400).json({
      success: false,
      error: "Email already exists",
    });
    return;
  }
  const hashPass = await hash(data.password, 10);
  const user = await UserModel.create({
    email: data.email,
    password: hashPass,
    name: data.name,
    role: data.role,
  });
  res.status(201).json({
    success: true,
    data: {
      _id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
    },
  });
});

app.post("/auth/login", async (req, res) => {
  const { success, data } = SignInSchema.safeParse(req.body);
  if (!success) {
    res.json({
      success: false,
      error: "Invalid request schema",
    });
    return;
  }
  const user = await UserModel.findOne({
    email: data.email,
  });
  if (!user) {
    res.status(400).json({
      success: false,
      error: "Invalid email or password",
    });
    return;
  }
  const isPasswordValid = await compare(data.password, user.password);
  if (!isPasswordValid) {
    res.status(400).json({
      success: false,
      error: "Invalid email or password",
    });
    return;
  }
  const token = jwt.sign(
    {
      role: user.role,
      userId: user._id,
    },
    process.env.JWT_PASSWORD!,
    { expiresIn: "7d" }
  );
  res.json({
    success: true,
    data: {
      token: token,
    },
  });
});

app.post("/auth/me", authMiddleware, async (req, res) => {
  const user = await UserModel.findOne({
    _id: req.userId,
  });
  if (!user) {
    res.status(404).json({
      success: false,
      error: "User not found",
    });
    return;
  }
  res.status(200).json({
    success: true,
    data: {
      _id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
    },
  });
});

app.post("/class", authMiddleware, teacherAuthMiddleware, async (req, res) => {
  const { success, data } = ClassSchema.safeParse(req.body);
  if (!success) {
    res.json({
      success: false,
      error: "Invalid request schema",
    });
    return;
  }
  const classDb = await ClassModel.create({
    className: data.className,
    teacherId: req.userId,
    studentIds: [],
  });
  res.status(201).json({
    success: true,
    data: {
      _id: classDb._id,
      className: classDb.className,
      teacherId: classDb.teacherId,
      studentIds: [],
    },
  });
});

app.post(
  "/class/:id/add-student",
  authMiddleware,
  teacherAuthMiddleware,
  async (req, res) => {
    const { success, data } = AddStudentSchema.safeParse(req.body);
    if (!success) {
      res.json({
        success: false,
        error: "Invalid request schema",
      });
      return;
    }
    const studentId = data.studentId;
    const classDb = await ClassModel.findOne({
      _id: req.params._id,
    });
    if (!classDb) {
      res.status(404).json({
        success: false,
        error: "Class not found",
      });
      return;
    }
    const userDb = await UserModel.findOne({
      _id: studentId,
    });
    if (!userDb) {
      res.status(404).json({
        success: false,
        error: "Student not found",
      });
      return;
    }
    if (req.userId !== classDb.teacherId.toString()) {
      res.status(403).json({
        success: false,
        error: "Forbidden, not class teacher",
      });
      return;
    }
    classDb.studentIds.push(new mongoose.Types.ObjectId(studentId));
    await classDb.save();
    res.status(200).json({
      success: true,
      data: {
        _id: classDb._id,
        className: classDb.className,
        teacherId: classDb.teacherId,
        studentIds: classDb.studentIds,
      },
    });
  }
);

app.listen(3000, () => {
  console.log("Running on Port: 3000");
});
