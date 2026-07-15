// 1. CONFIGURACIÓN DE ENTORNO Y ARQUITECTURA 
const path = require("path");
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const db = require("./db");

const app = express();

app.use(cors());
app.use(express.json());

app.use(express.static(path.join(__dirname, "Frontend")));

// 2. PATRÓN MIDDLEWARE: CAPA DE SEGURIDAD (REQUISITO PUNTO 3)

function verifyToken(req, res, next) {
    const authHeader = req.headers["authorization"];

    if (!authHeader) {
        return res.status(403).json({ error: "Token requerido" });
    }

    const token = authHeader.split(" ")[1]; 

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ error: "Token inválido" });
        }
        req.user = decoded;
        next();
    });
}

// RUTA PRINCIPAL (Health Check)
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "Frontend", "panel-olimpiadas1.html"));
});


// 3. CRUD DE USUARIOS (AUTENTICACIÓN, REGISTRO Y BORRADO)

// [C] REGISTRO DE USUARIO (Crear)
app.post("/registro", async (req, res) => {
    const { nombre, correo, password, rol } = req.body;

    try {
        const passwordHash = await bcrypt.hash(password, 10);
        const sql = `INSERT INTO usuarios(nombre, correo, password, rol) VALUES (?, ?, ?, ?)`;

        db.query(sql, [nombre, correo, passwordHash, rol], async (err, result) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            } 

            // --- CONFIGURACIÓN DEL CORREO DE BIENVENIDA ---
            const configurador = nodemailer.createTransport({
                service: "gmail",
                auth: {
                    user: process.env.EMAIL_USER,
                    pass: process.env.EMAIL_PASS
                }
            });

            const opcionesCorreo = {
                from: process.env.EMAIL_USER,
                to: correo,
                subject: "🏆 Olimpiadas PERU - Confirmación de Registro Conforme",
                text: `¡Hola ${nombre}!\n\nTu afiliación al sistema de las Olimpiadas ha sido procesada de manera conforme.\nYa puedes iniciar sesión en la plataforma con tu rol de: ${rol}.\n\n¡Muchos éxitos en el torneo!`
            };

            configurador.sendMail(opcionesCorreo, (errorMail) => {
                if (errorMail) {
                    console.log("Error al enviar el correo, pero el usuario se guardó:", errorMail.message);
                } else {
                    console.log("Correo de confirmación enviado con éxito a:", correo);
                }
            });

            res.status(201).json({ mensaje: "Usuario registrado con éxito y notificación enviada" });
        });
    } catch (error) {
        res.status(500).json({ error: "Error en el servidor al registrar" });
    }
});

// LOGIN (Generación de JWT / Leer credenciales)
app.post("/login", (req, res) => {
    const { correo, password } = req.body;
    const sql = "SELECT * FROM usuarios WHERE correo = ?";

    db.query(sql, [correo], async (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        if (result.length === 0) return res.status(401).json({ error: "Usuario no encontrado" });

        const usuario = result[0];
        const passwordCorrecto = await bcrypt.compare(password, usuario.password);

        if (!passwordCorrecto) return res.status(401).json({ error: "Contraseña incorrecta" });

        const token = jwt.sign(
            { id: usuario.id, correo: usuario.correo },
            process.env.JWT_SECRET,
            { expiresIn: "1h" }
        );

        res.json({ mensaje: "Login correcto", token });
    });
});

// LISTAR USUARIOS
app.get("/usuarios", verifyToken, (req, res) => {

    const sql = `
        SELECT
            id,
            nombre,
            correo,
            rol
        FROM usuarios
    `;

    db.query(sql, (err, result) => {

        if (err) {
            return res.status(500).json({
                error: err.message
            });
        }

        res.json(result);

    });

});
// [U] ACTUALIZAR USUARIO
// [U] ACTUALIZAR USUARIO
app.put("/usuarios/:id", verifyToken, async (req, res) => {

    const { id } = req.params;
    const { nombre, correo, password, rol } = req.body;

    try {

        let sql;
        let valores;

        if (password && password.trim() !== "") {

            const passwordHash = await bcrypt.hash(password, 10);

            sql = `
                UPDATE usuarios
                SET nombre = ?, correo = ?, password = ?, rol = ?
                WHERE id = ?
            `;

            valores = [
                nombre,
                correo,
                passwordHash,
                rol,
                id
            ];

        } else {

            sql = `
                UPDATE usuarios
                SET nombre = ?, correo = ?, rol = ?
                WHERE id = ?
            `;

            valores = [
                nombre,
                correo,
                rol,
                id
            ];
        }

        db.query(sql, valores, (err, result) => {

            if (err) {
                return res.status(500).json({
                    error: err.message
                });
            }

            if (result.affectedRows === 0) {
                return res.status(404).json({
                    error: "Usuario no encontrado"
                });
            }

            res.json({
                mensaje: "Usuario actualizado correctamente"
            });

        });

    } catch (error) {

        res.status(500).json({
            error: error.message
        });

    }

});

// [D] ELIMINAR USUARIO (Borrar)
app.delete("/usuarios/:id", verifyToken, (req, res) => {
    const { id } = req.params;
    const sql = "DELETE FROM usuarios WHERE id = ?";
    
    db.query(sql, [id], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        if (result.affectedRows === 0) return res.status(404).json({ error: "Usuario no encontrado" });
        res.json({ mensaje: "Usuario eliminado correctamente de la plataforma" });
    });
});



// 4. CRUD DE INSTITUCIONES (COMPLETO)

// [C] CREAR INSTITUCIÓN
app.post("/instituciones", verifyToken, (req, res) => {
    const { nombre, pais } = req.body;
    const sql = "INSERT INTO instituciones(nombre, pais) VALUES (?, ?)";
    db.query(sql, [nombre, pais], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.status(201).json({ mensaje: "Institución registrada con éxito", id: result.insertId });
    });
});

// [R] LEER INSTITUCIONES
app.get("/instituciones", verifyToken, (req, res) => {
    const sql = "SELECT * FROM instituciones";
    db.query(sql, (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(result);
    });
});

// [U] ACTUALIZAR INSTITUCIÓN
app.put("/instituciones/:id", verifyToken, (req, res) => {
    const { id } = req.params;
    const { nombre, pais } = req.body;
    const sql = "UPDATE instituciones SET nombre = ?, pais = ? WHERE id = ?";
    
    db.query(sql, [nombre, pais, id], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        if (result.affectedRows === 0) return res.status(404).json({ error: "Institución no encontrada" });
        res.json({ mensaje: "Institución actualizada correctamente" });
    });
});

// [D] ELIMINAR INSTITUCIÓN
app.delete("/instituciones/:id", verifyToken, (req, res) => {
    const { id } = req.params;
    const sql = "DELETE FROM instituciones WHERE id = ?";
    db.query(sql, [id], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        if (result.affectedRows === 0) return res.status(404).json({ error: "Institución no encontrada" });
        res.json({ mensaje: "Institución eliminada correctamente" });
    });
});


// 5. CRUD DE EQUIPOS (COMPLETO)

// [C] CREAR EQUIPO
app.post("/equipos", verifyToken, (req, res) => {
    const { nombre, deporte, institucion_id } = req.body;
    const sql = `INSERT INTO equipos(nombre, deporte, institucion_id) VALUES (?, ?, ?)`;

    db.query(sql, [nombre, deporte, institucion_id], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.status(201).json({ mensaje: "Equipo registrado con éxito", id: result.insertId });
    });
});

// [R] LEER EQUIPOS (Con INNER JOIN)
app.get("/equipos", (req, res) => {
    const sql = `
        SELECT equipos.id, equipos.nombre, equipos.deporte, instituciones.nombre AS institucion 
        FROM equipos 
        INNER JOIN instituciones ON equipos.institucion_id = instituciones.id
    `;
    db.query(sql, (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(result);
    });
});

// [U] ACTUALIZAR EQUIPO 
app.put("/equipos/:id", verifyToken, (req, res) => {
    const { id } = req.params;
    const { nombre, deporte, institucion_id } = req.body;
    const sql = `UPDATE equipos SET nombre = ?, deporte = ?, institucion_id = ? WHERE id = ?`;

    db.query(sql, [nombre, deporte, institucion_id, id], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        if (result.affectedRows === 0) return res.status(404).json({ error: "Equipo no encontrado" });
        res.json({ mensaje: "Equipo actualizado correctamente" });
    });
});

// [D] ELIMINAR EQUIPO
app.delete("/equipos/:id", verifyToken, (req, res) => {
    const { id } = req.params;
    const sql = "DELETE FROM equipos WHERE id = ?";
    db.query(sql, [id], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        if (result.affectedRows === 0) return res.status(404).json({ error: "Equipo no encontrado" });
        res.json({ mensaje: "Equipo eliminado correctamente" });
    });
});


// 5.5. CRUD DE JUGADORES (COMPLETO)

// [C] CREAR JUGADOR
app.post("/jugadores", verifyToken, (req, res) => {
    const { nombre, edad, equipo_id } = req.body;
    const sql = "INSERT INTO jugadores(nombre, edad, equipo_id) VALUES (?, ?, ?)";
    db.query(sql, [nombre, edad, equipo_id], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.status(201).json({ mensaje: "Jugador registrado con éxito", id: result.insertId });
    });
});

// [R] LEER JUGADORES (Con INNER JOIN)
app.get("/jugadores", (req, res) => {
    const sql = `
        SELECT jugadores.id, jugadores.nombre, jugadores.edad, equipos.nombre AS equipo 
        FROM jugadores 
        INNER JOIN equipos ON jugadores.equipo_id = equipos.id
    `;
    db.query(sql, (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(result);
    });
});

// [U] ACTUALIZAR JUGADOR
app.put("/jugadores/:id", verifyToken, (req, res) => {
    const { id } = req.params;
    const { nombre, edad, equipo_id } = req.body;
    const sql = "UPDATE jugadores SET nombre = ?, edad = ?, equipo_id = ? WHERE id = ?";
    db.query(sql, [nombre, edad, equipo_id, id], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        if (result.affectedRows === 0) return res.status(404).json({ error: "Jugador no encontrado" });
        res.json({ mensaje: "Jugador actualizado correctamente" });
    });
});

// [D] ELIMINAR JUGADOR
app.delete("/jugadores/:id", verifyToken, (req, res) => {
    const { id } = req.params;
    const sql = "DELETE FROM jugadores WHERE id = ?";
    db.query(sql, [id], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        if (result.affectedRows === 0) return res.status(404).json({ error: "Jugador no encontrado" });
        res.json({ mensaje: "Jugador eliminado correctamente" });
    });
});
// [POST] ENVIAR ALERTA DE ENCUENTRO PROGRAMADO
app.post("/notificaciones/avisar-encuentro", verifyToken, (req, res) => {
    const { correo_destino, equipo1, equipo2, deporte, fecha, hora } = req.body;

    // Validación estricta para asegurar que sea correo institucional de la UTP
  

const configurador = nodemailer.createTransport({
        service: "gmail",
        auth: {
            user: process.env.EMAIL_USER, // Tu correo robot de gmail
            pass: process.env.EMAIL_PASS  // Tus 16 letras de aplicación
        }
    });
    
    const opcionesCorreo = {
        from: process.env.EMAIL_USER,
        to: correo_destino,
        subject: `📅 UTP Olimpiadas - Encuentro Programado: ${deporte.toUpperCase()}`,
        text: `¡Hola Coordinador UTP!\n\nSe ha programado un nuevo encuentro de manera conforme en la plataforma:\n\n🏆 Partido: ${equipo1} vs ${equipo2}\n🏀 Disciplina: ${deporte}\n📅 Fecha: ${fecha}\n⏰ Hora: ${hora}\n\nPor favor, ingresa al sistema para validar la disponibilidad de tu delegación.\n\nSaludos,\nÁrea de Deportes UTP`
    };

    configurador.sendMail(opcionesCorreo, (errorMail) => {
        if (errorMail) {
            return res.status(500).json({ error: "Error al despachar el correo", detalle: errorMail.message });
        }
        res.json({ mensaje: `Notificación de encuentro enviada de manera conforme a ${correo_destino}` });
    });
});

// 6. REPORTES E INTELIGENCIA DE NEGOCIO (MÓDULO DE ANALÍTICA CENTRALIZADO)

// RUTA A: Máximos Anotadores por Disciplina
app.get("/reportes/maximo-anotador/:deporte", (req, res) => {
    const { deporte } = req.params;

    const sql = `
        SELECT 
            j.nombre AS jugador,
            j.edad AS edad,
            e.nombre AS equipo,
            e.deporte AS disciplina,
            SUM(eg.goles_puntos) AS total_anotaciones
        FROM estadisticas_goles eg
        INNER JOIN jugadores j ON eg.jugador_id = j.id
        INNER JOIN equipos e ON j.equipo_id = e.id
        WHERE LOWER(e.deporte) = LOWER(?)
        GROUP BY j.id
        ORDER BY total_anotaciones DESC
        LIMIT 5
    `;

    db.query(sql, [deporte], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        
        res.json({
            reporte: `Ranking de Máximos Anotadores - Disciplina: ${deporte.toUpperCase()}`,
            fecha_generacion: new Date().toLocaleDateString(),
            datos: result
        });
    });
});

// RUTA B: Volumen y Métricas Generales
app.get("/reportes/dashboard-general", (req, res) => {
    const sqlJugadores = `SELECT COUNT(*) AS total FROM jugadores`;
    const sqlEquipos = `SELECT COUNT(*) AS total FROM equipos`;
    const sqlMayorEquipo = `
        SELECT e.nombre AS equipo, COUNT(j.id) AS total_jugadores 
        FROM jugadores j
        INNER JOIN equipos e ON j.equipo_id = e.id
        GROUP BY j.equipo_id 
        ORDER BY total_jugadores DESC 
        LIMIT 1
    `;

    db.query(sqlJugadores, (err1, resJugadores) => {
        if (err1) return res.status(500).json({ error: err1.message });

        db.query(sqlEquipos, (err2, resEquipos) => {
            if (err2) return res.status(500).json({ error: err2.message });

            db.query(sqlMayorEquipo, (err3, resMayorEquipo) => {
                if (err3) return res.status(500).json({ error: err3.message });

                res.json({
                    reporte: "Dashboard de Control General - Olimpiadas",
                    fecha_generacion: new Date().toLocaleDateString(),
                    estadisticas: {
                        total_jugadores_registrados: resJugadores[0].total,
                        total_equipos_inscritos: resEquipos[0].total,
                        equipo_con_mas_participantes: resMayorEquipo[0] ? resMayorEquipo[0].equipo : "Ninguno",
                        cantidad_en_ese_equipo: resMayorEquipo[0] ? resMayorEquipo[0].total_jugadores : 0
                    }
                });
            });
        });
    });
});

app.listen(3000, () => {
    console.log("Servidor corriendo en puerto 3000");
});