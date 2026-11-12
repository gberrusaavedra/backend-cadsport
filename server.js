require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const JWT_SECRET = process.env.JWT_SECRET || 'cadsport_secreto_2026';

// Registro de usuario
app.post('/api/usuarios/registro', async (req, res) => {
  const { nombre, email, password } = req.body;
  try {
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO usuarios (nombre, email, password) VALUES ($1, $2, $3) RETURNING id, nombre, email',
      [nombre, email, hash]
    );
    res.status(201).json({ usuario: result.rows[0] });
  } catch (err) {
    res.status(400).json({ error: 'El correo ya está registrado o datos inválidos.' });
  }
});

// Inicio de sesión
app.post('/api/usuarios/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Correo o contraseña incorrectos.' });
    }
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, usuario: { id: user.id, nombre: user.nombre, email: user.email } });
  } catch (err) {
    res.status(500).json({ error: 'Error en el servidor.' });
  }
});

// Middleware de autenticación
function verificarToken(req, res, next) {
  const header = req.headers['authorization'];
  const token = header && header.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token requerido.' });
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Sesión expirada.' });
    req.userId = decoded.id;
    next();
  });
}

// Guardar proyecto CAD
app.post('/api/proyectos', verificarToken, async (req, res) => {
  const { nombre, configuracion } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO proyectos (usuario_id, nombre, configuracion) VALUES ($1, $2, $3) RETURNING id, nombre, creado_en',
      [req.userId, nombre, JSON.stringify(configuracion)]
    );
    res.status(201).json({ proyecto: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'No se pudo guardar el plano.' });
  }
});

// Listar proyectos del usuario
app.get('/api/proyectos', verificarToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, nombre, configuracion, creado_en FROM proyectos WHERE usuario_id = $1 ORDER BY creado_en DESC',
      [req.userId]
    );
    res.json({ proyectos: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'Error al obtener proyectos.' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor corriendo en puerto ${PORT}`));