// ================= IMPORTS =================
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");

// ================= CONFIG =================
const app = express();
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/smartclass";
const SECRET = process.env.JWT_SECRET || "smartclass_secret_key";

app.use(cors());
app.use(bodyParser.json());

// ================= DATABASE =================
mongoose.connect(MONGO_URI)
.then(()=>console.log("✅ MongoDB Connected"))
.catch(err=>console.log("❌ MongoDB Error:",err));

// ================= SCHEMAS =================
const userSchema = new mongoose.Schema({
  role:String,
  name:String,
  email:{type:String,unique:true},
  password:String
});

const facultySchema = new mongoose.Schema({
  name:String
});

const gradeSchema = new mongoose.Schema({
  year:String,
  branch:String,
  section:String,
  shift:String,
  capacity:Number
});

const classroomSchema = new mongoose.Schema({ name:String });
const labSchema = new mongoose.Schema({ name:String });

const subjectSchema = new mongoose.Schema({
  grade:String,
  subject:String,
  type:String,
  faculty:String
});

const scheduleSchema = new mongoose.Schema({
  grade:String,
  subject:String,
  faculty:String,
  classroom:String,
  day:String,
  time:String
});

const swapSchema = new mongoose.Schema({
  fromFaculty:String,
  toFaculty:String,
  grade:String,
  day:String,
  time:String,
  status:{type:String,default:"pending"}
});

const leaveSchema = new mongoose.Schema({
  faculty:String,
  from:String,
  to:String,
  reason:String,
  status:{type:String,default:"pending"}
});

const feedbackSchema = new mongoose.Schema({
  student:String,
  grade:String,
  message:String,
  timestamp:String
});

// ================= MODELS =================
const User = mongoose.model("User",userSchema);
const Faculty = mongoose.model("Faculty",facultySchema);
const Grade = mongoose.model("Grade",gradeSchema);
const Classroom = mongoose.model("Classroom",classroomSchema);
const Lab = mongoose.model("Lab",labSchema);
const Subject = mongoose.model("Subject",subjectSchema);
const Schedule = mongoose.model("Schedule",scheduleSchema);
const Swap = mongoose.model("Swap",swapSchema);
const Leave = mongoose.model("Leave",leaveSchema);
const Feedback = mongoose.model("Feedback",feedbackSchema);

// ================= JWT MIDDLEWARE =================
function verifyToken(req,res,next){
  const auth=req.headers["authorization"];
  if(!auth) return res.status(401).json({message:"No token"});
  const token=auth.split(" ")[1];
  jwt.verify(token,SECRET,(err,decoded)=>{
    if(err) return res.status(401).json({message:"Invalid token"});
    req.user=decoded;
    next();
  });
}

// ================= AUTH =================

// Signup (Admin only)
app.post("/signup",verifyToken,async(req,res)=>{
  if(req.user.role!=="admin")
    return res.status(403).json({message:"Only admin allowed"});

  const {role,name,email,password}=req.body;
  const hashed=bcrypt.hashSync(password,8);

  const user=new User({role,name,email,password:hashed});
  await user.save();
  res.json({message:"User created"});
});

// Login
app.post("/login",async(req,res)=>{
  const {role,email,password}=req.body;

  if(role==="teacher"){
    const faculty=await Faculty.findOne({
      name:{$regex:new RegExp("^"+email+"$","i")}
    });
    if(!faculty) return res.status(400).json({message:"Faculty not found"});

    const correctPassword=
      faculty.name.trim().charAt(0).toUpperCase()+"1234";

    if(password!==correctPassword)
      return res.status(400).json({message:"Invalid password"});

    const token=jwt.sign({role:"teacher",name:faculty.name},SECRET,{expiresIn:"2h"});
    return res.json({token,role:"teacher",name:faculty.name});
  }

  const user=await User.findOne({email,role});
  if(!user) return res.status(400).json({message:"Invalid credentials"});

  const valid=bcrypt.compareSync(password,user.password);
  if(!valid) return res.status(400).json({message:"Invalid credentials"});

  const token=jwt.sign({id:user._id,role:user.role,name:user.name},SECRET,{expiresIn:"2h"});
  res.json({token,role:user.role,name:user.name});
});

// ================= CRUD APIs =================

// Faculty
app.get("/faculty",async(req,res)=>res.json(await Faculty.find()));
app.post("/faculty",async(req,res)=>res.json(await new Faculty(req.body).save()));
app.delete("/faculty/:id",async(req,res)=>res.json(await Faculty.findByIdAndDelete(req.params.id)));

// Grades
app.get("/grades",async(req,res)=>res.json(await Grade.find()));
app.post("/grades",async(req,res)=>res.json(await new Grade(req.body).save()));

// Classrooms
app.get("/classrooms",async(req,res)=>res.json(await Classroom.find()));
app.post("/classrooms",async(req,res)=>res.json(await new Classroom(req.body).save()));

// Labs
app.get("/labs",async(req,res)=>res.json(await Lab.find()));
app.post("/labs",async(req,res)=>res.json(await new Lab(req.body).save()));

// Subjects
app.get("/subjects",async(req,res)=>res.json(await Subject.find()));
app.post("/subjects",async(req,res)=>res.json(await new Subject(req.body).save()));

// ================= TIMETABLE =================
app.get("/schedules",async(req,res)=>res.json(await Schedule.find()));

app.post("/schedules",async(req,res)=>{
  await Schedule.deleteMany({grade:req.body.grade});
  const saved=await Schedule.insertMany(req.body.schedules);
  res.json(saved);
});

app.delete("/schedules",async(req,res)=>{
  await Schedule.deleteMany({});
  res.json({message:"All schedules deleted"});
});

// ================= SWAPS =================
app.get("/swaps",async(req,res)=>res.json(await Swap.find()));

app.post("/swaps",async(req,res)=>{
  res.json(await new Swap(req.body).save());
});

app.put("/swaps/:id/approve",async(req,res)=>{
  const swap=await Swap.findByIdAndUpdate(req.params.id,{status:"approved"},{new:true});
  if(swap.toFaculty){
    await Schedule.findOneAndUpdate(
      {grade:swap.grade,day:swap.day,time:swap.time,faculty:swap.fromFaculty},
      {faculty:swap.toFaculty}
    );
  }
  res.json(swap);
});

app.put("/swaps/:id/reject",async(req,res)=>{
  res.json(await Swap.findByIdAndUpdate(req.params.id,{status:"rejected"},{new:true}));
});

app.delete("/swaps/:id",async(req,res)=>{
  res.json(await Swap.findByIdAndDelete(req.params.id));
});

// ================= LEAVES =================
app.get("/leaves",async(req,res)=>res.json(await Leave.find()));

app.post("/leaves",async(req,res)=>{
  res.json(await new Leave(req.body).save());
});

app.put("/leaves/:id",async(req,res)=>{
  res.json(await Leave.findByIdAndUpdate(req.params.id,req.body,{new:true}));
});

app.delete("/leaves/:id",async(req,res)=>{
  res.json(await Leave.findByIdAndDelete(req.params.id));
});

// ================= FEEDBACK =================
app.get("/feedback",async(req,res)=>res.json(await Feedback.find()));
app.post("/feedback",async(req,res)=>res.json(await new Feedback(req.body).save()));

// ================= START =================
app.listen(PORT,()=>console.log("🚀 Server running on http://localhost:"+PORT));