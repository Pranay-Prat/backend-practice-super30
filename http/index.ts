import express from "express";
import {
  AddStudentSchema,
  AttendanceSchema,
  ClassSchema,
  JwtPayload,
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
import expressWs from "express-ws";
import dotenv from "dotenv";
dotenv.config();
let activeSession: {
  classId: string;
  startedAt: string;
  attendance: Record<string, string>;
} | null = null;
const app = express();
expressWs(app);
app.use(express.json());
let allWs: any[] = [];
app.ws("/ws", function (ws, req) {
  try {
    const token = req.query.token;

    const decoded = jwt.verify(token, process.env.JWT_PASSWORD!) as JwtPayload;
    ws.user = { userId: decoded.userId, role: decoded.role };
    allWs.push(ws);
    ws.on("close", () => {
      allWs = allWs.filter((x) => x !== ws);
    });
    ws.on("message", async function (msg) {
      const message = msg.toString();
      let parsedData;
      try {
        parsedData = JSON.parse(message);
      } catch {
        ws.send(
          JSON.stringify({
            event: "ERROR",
            data: { message: "Invalid JSON format" },
          })
        );
        return;
      }
      if (!activeSession) {
        ws.send(
          JSON.stringify({
            event: "ERROR",
            data: {
              message: "No active attendance session",
            },
          })
        );

        return;
      }
      switch (parsedData.event) {
        case "ATTENDANCE_MARKED":
          if (ws.user.role === "teacher") {
            activeSession.attendance[parsedData.data.studentId] =
              parsedData.data.status;
            allWs.map((ws) =>
              ws.send(
                JSON.stringify({
                  event: "ATTENDANCE_MARKED",
                  data: {
                    studentId: parsedData.data.studentId,
                    status: parsedData.data.status,
                  },
                })
              )
            );
          } else {
            ws.send(
              JSON.stringify({
                event: "ERROR",
                data: {
                  message: "Forbidden, teacher event only",
                },
              })
            );
          }
          break;
        case "TODAY_SUMMARY":
          if (ws.user.role === "teacher") {
            const classDb = await ClassModel.findById(activeSession?.classId);
            const total = classDb?.studentIds.length ?? 0;
            const present = Object.keys(activeSession?.attendance || []).filter(
              (x) => activeSession?.attendance[x] === "present"
            ).length;
            const absent = total - present;
            allWs.map((ws) =>
              ws.send(
                JSON.stringify({
                event: "TODAY_SUMMARY",
                data: {
                  present: present,
                  absent: absent,
                  total: total,
                },
              })
              )
            );
          } else {
            ws.send(
              JSON.stringify({
                event: "ERROR",
                data: {
                  message: "Forbidden, teacher event only",
                },
              })
            );
          }
          break;
        case "MY_ATTENDANCE":
          if (ws.user.role === "student") {
            const status = activeSession?.attendance[ws.user.userId];
            if (status) {
              ws.send(
                JSON.stringify({
                  event: "MY_ATTENDANCE",
                  data: {
                    status: status,
                  },
                })
              );
              return;
            }
            ws.send(
              JSON.stringify({
                event: "MY_ATTENDANCE",
                data: {
                  status: "not yet updated",
                },
              })
            );
          } else {
            ws.send(
              JSON.stringify({
                event: "ERROR",
                data: {
                  message: "Forbidden, student event only",
                },
              })
            );
          }
          break;
        case "DONE":
          if (ws.user.role === "teacher") {
            const classDb = await ClassModel.findById(activeSession?.classId);
            const total = classDb?.studentIds.length ?? 0;
            const present = Object.keys(activeSession?.attendance || []).filter(
              (x) => activeSession?.attendance[x] === "present"
            ).length;
            const absent = total - present;
            const promises =
              classDb?.studentIds.map(async (studentId) => {
                await AttendanceModel.create({
                  studentId,
                  status:
                    activeSession?.attendance[studentId.toString()] ===
                    "present"
                      ? "present"
                      : "absent",
                });
              }) || [];
            await Promise.all(promises);
            activeSession = null;
            allWs.map((ws) =>
              ws.send(
                JSON.stringify({
                  event: "DONE",
                  data: {
                    message: "Attendance persisted",
                    present: present,
                    absent: absent,
                    total: total,
                  },
                })
              )
            );
          } else {
            ws.send(
              JSON.stringify({
                event: "ERROR",
                data: {
                  message: "Forbidden, teacher event only",
                },
              })
            );
          }
          break;
        default:
          ws.send("Invalid Operation");
      }
      console.log(msg);
    });
    console.log("socket", req.headers["authorization"]);
  } catch (error) {
    ws.send(
      JSON.stringify({
        event: "ERROR",
        data: {
          message: "Unauthorized or invalid token",
        },
      })
    );
    ws.close();
  }
});
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
      res.status(400).json({
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
