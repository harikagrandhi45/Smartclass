// server.js
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");

const app = express();
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/smartclass";
const SECRET = process.env.JWT_SECRET || "smartclass_secret_key"; // use env var in production

app.use(cors());
app.use(bodyParser.json());

// Connect to MongoDB
mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => {
    console.log("✅ Connected to MongoDB");
    seedDefaultAccounts().catch(err => console.error("Seed error:", err));
  })
  .catch(err => console.error("❌ MongoDB connection error:", err));

/* ===================== Schemas ===================== */
const userSchema = new mongoose.Schema({
  role: { type: String, required: true },
  name: String,
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true }
});

const facultySchema = new mongoose.Schema({ name: String });
const gradeSchema = new mongoose.Schema({
  year: String, branch: String, section: String, shift: String, capacity: Number
});
const classroomSchema = new mongoose.Schema({ name: String });
const labSchema = new mongoose.Schema({ name: String });
const subjectSchema = new mongoose.Schema({
  grade: String, subject: String, type: String, faculty: String
});
const scheduleSchema = new mongoose.Schema({
  grade: String, subject: String, faculty: String,
  classroom: String, day: String, time: String
});
const swapSchema = new mongoose.Schema({
  fromFaculty: String, toFaculty: String, grade: String,
  day: String, time: String, status: { type: String, default: "pending" }
});
const feedbackSchema = new mongoose.Schema({
  student: String, grade: String, message: String, timestamp: String
});

/* ===================== Models ===================== */
const User = mongoose.model("User", userSchema);
const Faculty = mongoose.model("Faculty", facultySchema);
const Grade = mongoose.model("Grade", gradeSchema);
const Classroom = mongoose.model("Classroom", classroomSchema);
const Lab = mongoose.model("Lab", labSchema);
const Subject = mongoose.model("Subject", subjectSchema);
const Schedule = mongoose.model("Schedule", scheduleSchema);
const SwapRequest = mongoose.model("SwapRequest", swapSchema);
const Feedback = mongoose.model("Feedback", feedbackSchema);

/* ========== helper: seed demo accounts ========== */
async function seedDefaultAccounts() {
  const demoStudentEmail = "student@smartclass.com";
  const demoAdminEmail = "admin@smartclass.com";

  const s = await User.findOne({ email: demoStudentEmail });
  if (!s) {
    const hashed = bcrypt.hashSync("Vignan", 8);
    await new User({ role: "student", name: "Demo Student", email: demoStudentEmail, password: hashed }).save();
    console.log("🔰 Seeded demo student:", demoStudentEmail);
  }

  const a = await User.findOne({ email: demoAdminEmail });
  if (!a) {
    const hashed = bcrypt.hashSync("Vignanfaculty", 8);
    await new User({ role: "admin", name: "Demo Admin", email: demoAdminEmail, password: hashed }).save();
    console.log("🔰 Seeded demo admin:", demoAdminEmail);
  }
}

/* ===================== Auth ===================== */
// Public Signup
app.post("/signup", async (req, res) => {
  try {
    const { role, name, email, password } = req.body;

    if (!role || !name || !email || !password) {
      return res.status(400).json({ message: "All fields required" });
    }

    // convert email to lowercase
    const normalizedEmail = email.toLowerCase();

    // check existing user
    const existing = await User.findOne({ email: normalizedEmail });
    if (existing) {
      return res.status(400).json({ message: "User already exists" });
    }

    const hashed = bcrypt.hashSync(password, 8);

    const user = new User({
      role,
      name,
      email: normalizedEmail,
      password: hashed
    });

    await user.save();

    res.json({ message: "Signup successful" });

  } catch (err) {
    console.log("Signup error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Login
app.post("/login", async (req, res) => {
  try {
    const { role, email, password } = req.body;

    if (!role || !email || !password)
      return res.status(400).json({ message: "Missing required fields" });

    /* ================= TEACHER LOGIN ================= */
    if (role === "teacher") {

      const faculty = await Faculty.findOne({
        name: { $regex: new RegExp("^" + email + "$", "i") }
      });

      if (!faculty)
        return res.status(400).json({ message: "Faculty not found" });

      const correctPassword =
        faculty.name.trim().charAt(0).toUpperCase() + "1234";

      if (password !== correctPassword)
        return res.status(400).json({ message: "Invalid password" });

      const token = jwt.sign(
        { role: "teacher", name: faculty.name },
        SECRET,
        { expiresIn: "1h" }
      );

      return res.json({
        message: "Faculty login successful",
        token,
        role: "teacher",
        name: faculty.name
      });
    }

    /* ================= STUDENT & ADMIN LOGIN ================= */

    const user = await User.findOne({ email, role });
    if (!user)
      return res.status(400).json({ message: "Invalid credentials" });

    const valid = bcrypt.compareSync(password, user.password);
    if (!valid)
      return res.status(400).json({ message: "Invalid credentials" });

    const token = jwt.sign(
      { email: user.email, role: user.role, id: user._id },
      SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      message: "Login successful",
      token,
      role: user.role,
      name: user.name
    });

  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

/* ========== example JWT middleware (use to protect routes) ========== */
function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"] || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ message: "No token provided" });
  jwt.verify(token, SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ message: "Failed to authenticate token" });
    req.user = decoded;
    next();
  });
}

/* ===================== CRUD APIs ===================== */
// Faculty
app.get("/faculty", async (req,res)=> res.json(await Faculty.find()));
app.post("/faculty", async (req,res)=> res.json(await new Faculty(req.body).save()));
app.put("/faculty/:id", async (req,res)=> res.json(await Faculty.findByIdAndUpdate(req.params.id, req.body,{new:true})));
app.delete("/faculty/:id", async (req,res)=> res.json(await Faculty.findByIdAndDelete(req.params.id)));

// Grades
app.get("/grades", async (req,res)=> res.json(await Grade.find()));
app.post("/grades", async (req,res)=> res.json(await new Grade(req.body).save()));
app.put("/grades/:id", async (req,res)=> res.json(await Grade.findByIdAndUpdate(req.params.id, req.body,{new:true})));
app.delete("/grades/:id", async (req,res)=> res.json(await Grade.findByIdAndDelete(req.params.id)));

// Classrooms
app.get("/classrooms", async (req,res)=> res.json(await Classroom.find()));
app.post("/classrooms", async (req,res)=> res.json(await new Classroom(req.body).save()));
app.delete("/classrooms/:id", async (req,res)=> res.json(await Classroom.findByIdAndDelete(req.params.id)));

// Labs
app.get("/labs", async (req,res)=> res.json(await Lab.find()));
app.post("/labs", async (req,res)=> res.json(await new Lab(req.body).save()));
app.delete("/labs/:id", async (req,res)=> res.json(await Lab.findByIdAndDelete(req.params.id)));

// Subjects
app.get("/subjects", async (req,res)=> res.json(await Subject.find()));
app.post("/subjects", async (req,res)=> res.json(await new Subject(req.body).save()));
app.put("/subjects/:id", async (req,res)=> res.json(await Subject.findByIdAndUpdate(req.params.id, req.body,{new:true})));
app.delete("/subjects/:id", async (req,res)=> res.json(await Subject.findByIdAndDelete(req.params.id)));

// Timetable (Schedules)
app.get("/schedules", async (req,res)=> res.json(await Schedule.find()));
app.post("/schedules", async (req,res)=> {
  await Schedule.deleteMany({ grade: req.body.grade }); // reset timetable for grade
  const saved = await Schedule.insertMany(req.body.schedules);
  res.json(saved);
});
app.put("/schedules/:id", async (req,res)=> res.json(await Schedule.findByIdAndUpdate(req.params.id, req.body,{new:true})));
app.delete("/schedules/:id", async (req,res)=> res.json(await Schedule.findByIdAndDelete(req.params.id)));

// Swap Requests
app.get("/swaps", async (req,res)=> res.json(await SwapRequest.find()));
app.post("/swaps", async (req,res)=> res.json(await new SwapRequest(req.body).save()));
app.put("/swaps/:id/approve", async (req,res)=> {
  const swap = await SwapRequest.findByIdAndUpdate(req.params.id, { status:"approved" }, { new:true });
  // Update schedule with substitute
  if (swap.toFaculty) {
    await Schedule.findOneAndUpdate(
      { grade: swap.grade, day: swap.day, time: swap.time, faculty: swap.fromFaculty },
      { faculty: swap.toFaculty }
    );
  }
  res.json(swap);
});
app.put("/swaps/:id/reject", async (req,res)=> res.json(await SwapRequest.findByIdAndUpdate(req.params.id, { status:"rejected" }, { new:true})));
app.delete("/swaps/:id", async (req,res)=> res.json(await SwapRequest.findByIdAndDelete(req.params.id)));
const leaveSchema = new mongoose.Schema({
  faculty: String,
  from: String,
  to: String,
  reason: String,
  status: { type: String, default: "pending" }
});

const Leave = mongoose.model("Leave", leaveSchema);

// Feedback
app.get("/feedback", async (req,res)=> res.json(await Feedback.find()));
app.post("/feedback", async (req,res)=> res.json(await new Feedback(req.body).save()));
app.delete("/feedback/:id", async (req,res)=> res.json(await Feedback.findByIdAndDelete(req.params.id)));

/* ===================== Start Server ===================== */
app.listen(PORT, () => console.log(`✅ Server running on http://localhost:${PORT}`));
// Clear all schedules
app.delete("/schedules", async (req,res)=> {
  await Schedule.deleteMany({});
  res.json({ message: "All schedules deleted" });
});
// Delete all schedules
app.delete("/schedules", async (req,res)=>{
  await Schedule.deleteMany({});
  res.json({message:"All schedules deleted"});
});




