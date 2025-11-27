import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

dotenv.config();

const app = express();

// Configuración básica
app.use(
  cors({
    origin: "http://localhost:5173", // Vite frontend
    credentials: true,
  })
);
app.use(express.json());

// ------------------ CONEXIÓN A MONGO ------------------
const uri = process.env.MONGO_URI;

mongoose
  .connect(uri)
  .then(() => console.log("✅ Conectado a MongoDB"))
  .catch((err) => console.error("❌ Error de conexión a MongoDB:", err));

// ------------------ MODELO USER ------------------
const userSchema = new mongoose.Schema(
  {
    nombre: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    passwordHash: { type: String, required: true },

    // 👇 NUEVO: campo de rol con default "ciudadano"
    role: {
      type: String,
      enum: ["ciudadano", "tecnico", "admin"],
      default: "ciudadano",
    },
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);

// ------------------ MODELO MEDICION ------------------
const medicionSchema = new mongoose.Schema(
  {
    // Quién hizo la medición
    usuario: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },

    // Datos básicos que ya usa el front
    fecha: { type: Date, required: true },

    // Dirección legible (string)
    ubicacion: { type: String, default: "" },

    // 👇 NUEVO: coordenadas numéricas para el mapa
    lat: { type: Number },
    lng: { type: Number },

    ph: { type: Number, required: true },
    cloro: { type: Number, required: true },
    turbidez: { type: Number, required: true },
    tds: { type: Number, required: true },

    // Resumen por parámetro (igual que en el front)
    resumen: {
      ph: { type: String, enum: ["ok", "alto", "bajo", "vacio"], required: true },
      cloro: { type: String, enum: ["ok", "alto", "bajo", "vacio"], required: true },
      turbidez: { type: String, enum: ["ok", "alto", "bajo", "vacio"], required: true },
      tds: { type: String, enum: ["ok", "alto", "bajo", "vacio"], required: true },
    },

    fuente: {
      type: String,
      enum: ["ciudadano", "tecnico", "sensor"],
      default: "ciudadano",
    },
    validada: {
      type: Boolean,
      default: false,
    },
  },
  { timestamps: true }
);


const Medicion = mongoose.model("Medicion", medicionSchema);


// ------------------ HELPERS ------------------
function generarToken(user) {
  return jwt.sign(
    {
      id: user._id,
      email: user.email,
      nombre: user.nombre,
      role: user.role, // 👈 NUEVO: incluir rol en el token
    },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
}

// ------------------ MIDDLEWARE AUTH ------------------
function auth(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;

  if (!token) {
    return res.status(401).json({ message: "No autorizado" });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    // payload: { id, email, nombre, role }
    req.user = {
      id: payload.id,
      email: payload.email,
      nombre: payload.nombre,
      role: payload.role,
    };
    next();
  } catch (err) {
    console.error("Error en auth middleware:", err);
    return res.status(401).json({ message: "Token inválido o expirado" });
  }
}

function requireRole(roles = []) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ message: "No tienes permisos para esta acción" });
    }
    next();
  };
}


// ------------------ RUTAS AUTH ------------------

// Registro
app.post("/api/auth/register", async (req, res) => {
  try {
    const { nombre, email, password } = req.body;

    if (!nombre || !email || !password) {
      return res.status(400).json({ message: "Todos los campos son obligatorios" });
    }

    const existente = await User.findOne({ email });
    if (existente) {
      return res.status(409).json({ message: "El correo ya está registrado" });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    // 👇 role NO viene del frontend, se usa el default "ciudadano"
    const user = await User.create({ nombre, email, passwordHash });

    const token = generarToken(user);

    res.status(201).json({
      user: {
        id: user._id,
        nombre: user.nombre,
        email: user.email,
        role: user.role, // 👈 NUEVO
      },
      token,
    });
  } catch (err) {
    console.error("Error en /register:", err);
    res.status(500).json({ message: "Error en el servidor" });
  }
});

// Login
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: "Credenciales inválidas" });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ message: "Credenciales inválidas" });

    const token = generarToken(user);

    res.json({
      user: {
        id: user._id,
        nombre: user.nombre,
        email: user.email,
        role: user.role, // 👈 NUEVO
      },
      token,
    });
  } catch (err) {
    console.error("Error en /login:", err);
    res.status(500).json({ message: "Error en el servidor" });
  }
});

// ------------------ RUTAS DE MEDICIONES ------------------

app.post("/api/mediciones", auth, async (req, res) => {
  try {
    console.log("POST /api/mediciones body:", req.body); // 👈 para ver qué llega

    const body = req.body || {};

    const {
      fecha,
      ubicacion,
      ph,
      cloro,
      turbidez,
      tds,
      resumen,
      lat,
      lng,
    } = body;

    if (
      !fecha ||
      ph === undefined ||
      cloro === undefined ||
      turbidez === undefined ||
      tds === undefined ||
      !resumen
    ) {
      return res
        .status(400)
        .json({ message: "Faltan datos de la medición (fecha, parámetros o resumen)" });
    }

    const doc = await Medicion.create({
      usuario: req.user.id,
      fecha: new Date(fecha),
      ubicacion: ubicacion || "",

      // 👇 Guardamos coordenadas numéricas si vienen
      lat:
        typeof lat === "number"
          ? lat
          : lat != null
          ? Number(lat)
          : undefined,
      lng:
        typeof lng === "number"
          ? lng
          : lng != null
          ? Number(lng)
          : undefined,

      ph,
      cloro,
      turbidez,
      tds,
      resumen,
      fuente: req.user.role === "tecnico" ? "tecnico" : "ciudadano",
    });

    res.status(201).json(doc);
  } catch (err) {
    console.error("Error en POST /api/mediciones:", err);
    res.status(500).json({ message: "Error al guardar la medición" });
  }
});

// Historial del usuario logueado
app.get("/api/mediciones/mias", auth, async (req, res) => {
  try {
    const docs = await Medicion.find({ usuario: req.user.id })
      .sort({ fecha: -1, createdAt: -1 })
      .lean();

    res.json(docs);
  } catch (err) {
    console.error("Error en GET /api/mediciones/mias:", err);
    res.status(500).json({ message: "Error al obtener tus mediciones" });
  }
});

// Todas las mediciones (para cualquier usuario logueado)
app.get("/api/mediciones", auth, async (req, res) => {
  try {
    console.log("GET /api/mediciones usuario:", req.user); // 👈 para ver quién llama

    const docs = await Medicion.find({})
      .sort({ fecha: -1, createdAt: -1 })
      .limit(500) // para no explotar el mapa al inicio
      .lean();

    res.json(docs);
  } catch (err) {
    console.error("Error en GET /api/mediciones:", err);
    res.status(500).json({ message: "Error al obtener mediciones" });
  }
});



// Ruta protegida de ejemplo para Admin
app.get("/api/admin/me", async (req, res) => {
  try {
    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
    if (!token) return res.status(401).json({ message: "No autorizado" });

    const payload = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(payload.id).select("nombre email role createdAt"); // 👈 incluir role
    if (!user) return res.status(404).json({ message: "Usuario no encontrado" });

    res.json({ user });
  } catch (err) {
    console.error("Error en /admin/me:", err);
    res.status(401).json({ message: "Token inválido o expirado" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Backend escuchando en http://localhost:${PORT}`);
});