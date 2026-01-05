import express from "express";
import {
  AddStudentSchema,
  AttendanceSchema,
  ClassSchema,
  SignInSchema,
  SignUpSchema,
} from "./types/types";

import { AttendanceModel, ClassModel, UserModel } from "./model/models";
import { compare, hash } from "bcryptjs";
import * as jwt from "jsonwebtoken";
import {
  authMiddleware,
  studentAuthMiddleware,
  teacherAuthMiddleware,
} from "./middleware";
import mongoose from "mongoose";
import dotenv from "dotenv";
dotenv.config();
let activeSession: {
  classId: string;
  startedAt: string;
  attendance: Record<string, string>;
} | null = null;
const app = express();
app.use(express.json());

app.post("/auth/signup", async (req, res) => {
  const { success, data } = SignUpSchema.safeParse(req.body);
  if (!success) {
    res.status(400).json({
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
    res.status(400).json({
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

app.get("/auth/me", authMiddleware, async (req, res) => {
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
    res.status(400).json({
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
    if (!studentId) {
      res.status(400).json({
        success: false,
        error: "StudentId not found",
      });
    }
    const classDb = await ClassModel.findOne({
      _id: req.params.id,
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
    if (classDb.studentIds.some((id) => id.equals(studentId))) {
      return res.status(200).json({
        success: true,
        data: {
          _id: classDb._id,
          className: classDb.className,
          teacherId: classDb.teacherId,
          studentIds: classDb.studentIds,
        },
      });
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

app.get("/class/:id", authMiddleware, async (req, res) => {
  const classDb = await ClassModel.findOne({
    _id: req.params.id,
  });
  if (!classDb) {
    res.status(404).json({
      success: false,
      error: "Class not found",
    });
    return;
  }
  const isTeacher = classDb.teacherId.equals(req.userId);
  const isStudent = classDb.studentIds.some((id) => id.equals(req.userId));

  if (isTeacher || isStudent) {
    const students = await UserModel.find({
      _id: classDb.studentIds,
    });
    res.status(200).json({
      success: true,
      data: {
        _id: classDb._id,
        className: classDb.className,
        teacherId: classDb.teacherId,
        students: students.map((s) => ({
          _id: s._id,
          name: s.name,
          email: s.email,
        })),
      },
    });
  } else {
    res.status(403).json({
      success: false,
      error: "Forbidden, not class teacher",
    });
    return;
  }
});

app.get(
  "/students",
  authMiddleware,
  teacherAuthMiddleware,
  async (req, res) => {
    const users = await UserModel.find({
      role: "student",
    });
    res.status(200).json({
      success: true,
      data: users.map((user) => ({
        _id: user._id,
        name: user.name,
        email: user.email,
      })),
    });
  }
);

app.get(
  "/class/:id/my-attendance",
  authMiddleware,
  studentAuthMiddleware,
  async (req, res) => {
    const classId = req.params.id;
    const classDb = await ClassModel.findById(classId);
    if (!classDb) {
      res.status(404).json({
        success: false,
        error: "Class not found",
      });
      return;
    }

    const isEnrolled = classDb.studentIds.some((id) => id.equals(req.userId));
    if (!isEnrolled) {
      res.status(403).json({
        success: false,
        error: "Forbidden",
      });
      return;
    }
    const attendance = await AttendanceModel.findOne({
      classId: classId,
      studentId: req.userId,
    });
    if (attendance) {
      return res.status(200).json({
        success: true,
        data: {
          classId: classId,
          status: "present",
        },
      });
    } else {
      return res.status(200).json({
        success: true,
        data: {
          classId: classId,
          status: null,
        },
      });
    }
  }
);

app.post(
  "/attendance/start",
  authMiddleware,
  teacherAuthMiddleware,
  async (req, res) => {
    const { success, data } = AttendanceSchema.safeParse(req.body);
    if (!success) {
      res.json({
        success: false,
        error: "Invalid request schema",
      });
      return;
    }
    const classId = data.classId;
    if (!classId) {
      res.status(400).json({
        success: false,
        error: "ClassId not found",
      });
    }
    const classDb = await ClassModel.findOne({
      _id: classId,
    });
    if (!classDb) {
      res.status(404).json({
        success: false,
        error: "Class not found",
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
    activeSession = {
      classId: classId,
      startedAt: new Date().toISOString(),
      attendance: {},
    };
    res.status(200).json({
      success: true,
      data: {
        classId: classId,
        startedAt: activeSession.startedAt,
      },
    });
  }
);
app.listen(3000, () => {
  console.log("Running on Port: 3000");
});
