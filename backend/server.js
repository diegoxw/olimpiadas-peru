// 1. Cargar las variables de entorno desde el .env (REQUISITO PUNTO 4)
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const db = require("./db");

const app = express();

app.use(cors());
app.use(express.json());


//           MIDDLEWARE JWT PROTEGIDO 

function verifyToken(req, res, next) {
    const authHeader = req.headers["authorization"];

    if (!authHeader) {
        return res.status(403).send("Token requerido");
    }

    const token = authHeader.split(" ")[1]; 

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).send("Token inválido");
        }
        req.user = decoded;
        next();
    });
}

//                RUTA PRINCIPAL
app.get("/", (req, res) => {
    res.send("Servidor de Olimpiadas funcionando correctamente");
});

//           AUTENTICACIÓN Y ENCRIPCION 


// REGISTRO DE USUARIO
app.post("/registro", async (req, res) => {
    const { nombre, correo, password, rol } = req.body;

    try {
        const passwordHash = await bcrypt.hash(password, 10);
        const sql = `INSERT INTO usuarios(nombre, correo, password, rol) VALUES (?, ?, ?, ?)`;

        db.query(sql, [nombre, correo, passwordHash, rol], (err, result) => {
            if (err) {
                res.status(500).send(err);
            } else {
                res.send("Usuario registrado");
            }
        });
    } catch (error) {
        res.status(500).send(error);
    }
});

// LOGIN 
app.post("/login", (req, res) => {
    const { correo, password } = req.body;
    const sql = "SELECT * FROM usuarios WHERE correo = ?";

    db.query(sql, [correo], async (err, result) => {
        if (err) return res.status(500).send(err);
        if (result.length === 0) return res.status(401).send("Usuario no encontrado");

        const usuario = result[0];
        const passwordCorrecto = await bcrypt.compare(password, usuario.password);

        if (!passwordCorrecto) return res.status(401).send("Contraseña incorrecta");

        const token = jwt.sign(
            { id: usuario.id, correo: usuario.correo },
            process.env.JWT_SECRET,
            { expiresIn: "1h" }
        );

        res.json({ mensaje: "Login correcto", token });
    });
});

//              CRUD INSTITUCIONES

app.get("/instituciones", verifyToken, (req, res) => {
    const sql = "SELECT * FROM instituciones";
    db.query(sql, (err, result) => {
        if (err) res.status(500).send(err);
        else res.json(result);
    });
});

app.post("/instituciones", (req, res) => {
    const { nombre, pais } = req.body;
    const sql = "INSERT INTO instituciones(nombre, pais) VALUES (?, ?)";
    db.query(sql, [nombre, pais], (err, result) => {
        if (err) res.status(500).send(err);
        else res.send("Institución registrada");
    });
});

//                CRUD DE EQUIPOS 

// REGISTRAR EQUIPO 
app.post("/equipos", verifyToken, (req, res) => {
    const { nombre, deporte, institucion_id } = req.body;
    const sql = `INSERT INTO equipos(nombre, deporte, institucion_id) VALUES (?, ?, ?)`;

    db.query(sql, [nombre, deporte, institucion_id], (err, result) => {
        if (err) return res.status(500).send(err);
        res.status(201).json({ mensaje: "Equipo registrado con éxito" });
    });
});

// LISTAR EQUIPOS 
app.get("/equipos", (req, res) => {
    const sql = `
        SELECT equipos.id, equipos.nombre, equipos.deporte, instituciones.nombre AS institucion 
        FROM equipos 
        INNER JOIN instituciones ON equipos.institucion_id = instituciones.id
    `;
    db.query(sql, (err, result) => {
        if (err) return res.status(500).send(err);
        res.json(result);
    });
});

app.delete("/equipos/:id", verifyToken, (req, res) => {
    const { id } = req.params;
    const sql = "DELETE FROM equipos WHERE id = ?";
    db.query(sql, [id], (err, result) => {
        if (err) return res.status(500).send(err);
        res.json({ mensaje: "Equipo eliminado correctamente" });
    });
});

app.listen(3000, () => {
    console.log("Servidor corriendo en puerto 3000");
});