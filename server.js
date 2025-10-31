// server.js
import express from "express";
import mongoose from "mongoose";
import bodyParser from "body-parser";
import path from "path";
import { fileURLToPath } from "url";
import axios from "axios";
import bcrypt from "bcryptjs"; // <- changed to bcryptjs

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = 3000;

// ===== Google reCAPTCHA Secret Key =====
const RECAPTCHA_SECRET = "6Lfoy-krAAAAAAKrP00hOys480KNKU86TJaaNDhW"; // keep your own key

// ===== Middleware =====
app.use(express.static(__dirname));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// ===== MongoDB Connection =====
mongoose
  .connect("mongodb://127.0.0.1:27017/loginSystem", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

// ===== User Schema =====
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, maxlength: 30 },
  password: { type: String, required: true },
});
const User = mongoose.model("User", userSchema);

// ===== Password Strength Function =====
function isStrongPassword(password) {
  const regex =
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
  return regex.test(password);
}

// ===== REGISTER =====
app.post("/register", async (req, res) => {
  const { username, password, token } = req.body;

  if (!username || !password)
    return res.json({ success: false, message: "All fields required." });

  if (username.length > 30)
    return res.json({ success: false, message: "Username too long (max 30 chars)." });

  if (!isStrongPassword(password))
    return res.json({
      success: false,
      message:
        "Password must include uppercase, lowercase, number, special characters and have at least 8 characters.",
    });

  if (!token)
    return res.json({ success: false, message: "Please complete CAPTCHA." });

  try {
    // Verify reCAPTCHA
    const captchaUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${RECAPTCHA_SECRET}&response=${token}`;
    const captchaResp = await axios.post(captchaUrl);
    if (!captchaResp.data.success)
      return res.json({ success: false, message: "CAPTCHA verification failed." });

    const existing = await User.findOne({ username });
    if (existing)
      return res.json({ success: false, message: "User already exists." });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();
    res.json({ success: true, message: "Registration successful!" });
  } catch (err) {
    console.error(err);
    res.json({ success: false, message: "Error registering user." });
  }
});

// ===== LOGIN =====
app.post("/login", async (req, res) => {
  const { username, password, token } = req.body;

  if (!token)
    return res.json({ success: false, message: "Please complete CAPTCHA." });

  try {
    // Verify reCAPTCHA
    const captchaUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${RECAPTCHA_SECRET}&response=${token}`;
    const captchaResp = await axios.post(captchaUrl);
    if (!captchaResp.data.success)
      return res.json({ success: false, message: "CAPTCHA verification failed." });

    const user = await User.findOne({ username });
    if (!user)
      return res.json({ success: false, message: "Invalid username or password." });

    const validPass = await bcrypt.compare(password, user.password);
    if (!validPass)
      return res.json({ success: false, message: "Invalid username or password." });

    res.json({ success: true, message: "Login successful!" });
  } catch (err) {
    console.error(err);
    res.json({ success: false, message: "Error logging in." });
  }
});

// ===== Serve Welcome Page =====
app.get("/welcome", (req, res) => {
  res.sendFile(path.join(__dirname, "welcome.html"));
});

// ===== Start Server =====
app.listen(PORT, () =>
  console.log(`🚀 Server running at http://localhost:${PORT}`)
);

