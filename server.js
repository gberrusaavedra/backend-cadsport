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

const JWT_SECRET = process.env.JWT_SECRET || 'cadsport_secreto_super_seguro_2026';

// 1. Registro de usuario (con palabra secreta)
app.post('/api/usuarios/registro', async (req, res) => {
  const { nombre, email, password, palabraSecreta } = req.body;
  if (!nombre || !email || !password || !palabraSecreta) {
    return res.status(400).json({ error: 'Todos los campos (incluida la palabra secreta) son obligatorios.' });
  }

  try {
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO usuarios (nombre, email, password, palabra_secreta) VALUES ($1, $2, $3, $4) RETURNING id, nombre, email',
      [nombre.trim(), email.trim().toLowerCase(), hash, palabraSecreta.trim()]
    );
    res.status(201).json({ usuario: result.rows[0] });
  } catch (err) {
    console.error('Error en registro:', err);
    res.status(400).json({ error: 'El correo ya está registrado o hubo un error al crear la cuenta.' });
  }
});

// 2. Inicio de sesión (Login)
app.post('/api/usuarios/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query(
      'SELECT * FROM usuarios WHERE LOWER(email) = LOWER($1)',
      [email.trim()]
    );
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Correo o contraseña incorrectos.' });
    }

    const usuario = result.rows[0];
    const valido = await bcrypt.compare(password, usuario.password);
    if (!valido) {
      return res.status(401).json({ error: 'Correo o contraseña incorrectos.' });
    }

    const token = jwt.sign(
      { id: usuario.id, email: usuario.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      token,
      usuario: { id: usuario.id, nombre: usuario.nombre, email: usuario.email }
    });
  } catch (err) {
    console.error('Error en login:', err);
    res.status(500).json({ error: 'Error interno del servidor al iniciar sesión.' });
  }
});

// 3. Recuperar contraseña mediante palabra secreta
app.post('/api/usuarios/recuperar-password', async (req, res) => {
  const { email, palabraSecreta, nuevaPassword } = req.body;

  if (!email || !palabraSecreta || !nuevaPassword || nuevaPassword.length < 6) {
    return res.status(400).json({ error: 'Completa el correo, la palabra secreta y una nueva contraseña (mínimo 6 caracteres).' });
  }

  try {
    const result = await pool.query(
      'SELECT id, palabra_secreta FROM usuarios WHERE LOWER(email) = LOWER($1)',
      [email.trim()]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'No existe una cuenta registrada con ese correo.' });
    }

    const usuario = result.rows[0];
    if (!usuario.palabra_secreta || usuario.palabra_secreta.trim().toLowerCase() !== palabraSecreta.trim().toLowerCase()) {
      return res.status(401).json({ error: 'La palabra secreta no coincide.' });
    }

    const nuevoHash = await bcrypt.hash(nuevaPassword, 10);
    await pool.query(
      'UPDATE usuarios SET password = $1 WHERE id = $2',
      [nuevoHash, usuario.id]
    );

    res.json({ mensaje: 'Contraseña actualizada correctamente.' });
  } catch (err) {
    console.error('Error al recuperar contraseña:', err);
    res.status(500).json({ error: 'Error interno al actualizar la contraseña.' });
  }
});

// Middleware de verificación de token JWT
function verificarToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token no proporcionado.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Sesión expirada o inválida.' });
    req.user = user;
    next();
  });
}

// 4. Guardar proyecto/plano deportivo en Neon
app.post('/api/proyectos', verificarToken, async (req, res) => {
  const { nombre, configuracion } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO proyectos (usuario_id, nombre, configuracion) VALUES ($1, $2, $3) RETURNING *',
      [req.user.id, nombre, JSON.stringify(configuracion)]
    );
    res.status(201).json({ proyecto: result.rows[0] });
  } catch (err) {
    console.error('Error al guardar proyecto:', err);
    res.status(500).json({ error: 'No se pudo guardar el proyecto en la base de datos.' });
  }
});

// 5. Listar proyectos del usuario
app.get('/api/proyectos', verificarToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM proyectos WHERE usuario_id = $1 ORDER BY id DESC',
      [req.user.id]
    );
    res.json({ proyectos: result.rows });
  } catch (err) {
    console.error('Error al listar proyectos:', err);
    res.status(500).json({ error: 'Error al obtener los proyectos.' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor CAD Sport ejecutándose en puerto ${PORT}`);
});