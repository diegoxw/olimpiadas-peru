const mysql = require("mysql2"); // Se importa una sola vez aquí arriba

const connection = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

connection.connect((err) => {
    if (err) {
        console.log("Error de conexión a la Base de Datos:", err.message);
    } else {
        console.log("MySQL conectado con éxito a la BD 'olimpiadas'");
    }
});

module.exports = connection;