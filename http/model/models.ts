import mongoose from "mongoose";
mongoose.connect(process.env.MONGO_URL!)
const UserSchema = new mongoose.Schema({
    name: String,
    email: {type: String, unique:true},
    password : {type:String, required:true},
    role: {
    type: String,
    enum: ["teacher","student"],
    required: true,
  },
})
const ClassSchema = new mongoose.Schema({
    className: {
      type: String,
      required: true,
      trim: true,
    },
    teacherId: {
        type: mongoose.Types.ObjectId,
        ref: "User",
        required: true
    },
    studentIds:[
       {
        type: mongoose.Types.ObjectId,
        ref: "User"
       } 
    ]
})
const AttendanceSchema = new mongoose.Schema({
    classId: {
        type: mongoose.Types.ObjectId,
        ref:"Class"
    },
    studentId:{
        type:mongoose.Types.ObjectId,
        ref:"User"
    },
    status:{
        type:String,
        enum:["present","absent"],
        required:true
    }
})
export const AttendanceModel = mongoose.model("Attendance", AttendanceSchema)
export const ClassModel = mongoose.model("Class", ClassSchema)
export const UserModel = mongoose.model("User", UserSchema)