/**
 * @file server.js
 * @description Punto de entrada de la API Bank-Grade JWT. Configura la
 * aplicación Express, la conexión a Redis (utilizada como capa de control
 * de sesiones) y registra las rutas públicas, protegidas y de autenticación.
 *
 * @module app
 * @requires express
 * @requires ioredis
 * @requires ./config/env.js
 * @requires ./routes/auth.routes.js
 * @requires ./middleware/auth.middleware.js
 */

import express from "express";
import Redis from "ioredis";

import { env } from "./config/env.js";
import authRoutes from "./routes/auth.routes.js";
import { authenticate } from "./middleware/auth.middleware.js";

/**
 * Instancia principal de la aplicación Express.
 * @constant
 * @type {import("express").Express}
 */
const app = express();

/**
 * Cliente de Redis utilizado para el control de sesiones (creación,
 * consulta, rotación y revocación de sesiones asociadas a los tokens JWT).
 *
 * @constant
 * @type {Redis}
 * @see {@link module:services/session.service} para el uso detallado de Redis.
 */
const redis = new Redis({
    host: env.redis.host,
    port: env.redis.port
});

/**
 * Middleware global que habilita el parseo de cuerpos de petición en
 * formato JSON para todas las rutas de la aplicación.
 */
app.use(express.json());

/**
 * Registra las rutas de autenticación bajo el prefijo `/api/auth`.
 *
 * Endpoints expuestos por este router:
 * - `POST /api/auth/login`
 * - `POST /api/auth/refresh`
 * - `POST /api/auth/logout`
 *
 * @see module:routes/auth.routes
 */
app.use(
    "/api/auth",
    authRoutes
);

/**
 * Endpoint de healthcheck del servicio.
 *
 * Verifica la disponibilidad de la API y su conectividad con Redis
 * mediante un comando `PING`. Se utiliza normalmente para monitoreo,
 * balanceadores de carga y orquestadores (Docker, Kubernetes, etc.).
 *
 * @name GET/health
 * @function
 * @async
 * @param {import("express").Request} req - Objeto de la petición HTTP.
 * @param {import("express").Response} res - Objeto de la respuesta HTTP.
 *
 * @returns {void} Responde con:
 * - `200 OK` y `{ status: "ok", service, redis }` si Redis responde correctamente.
 * - `503 Service Unavailable` y `{ status: "error", service, redis: "unavailable" }`
 *   si la conexión con Redis falla.
 *
 * @example
 * // Respuesta exitosa (200)
 * {
 *   "status": "ok",
 *   "service": "bank-grade-api",
 *   "redis": "PONG"
 * }
 *
 * @example
 * // Respuesta con Redis caído (503)
 * {
 *   "status": "error",
 *   "service": "bank-grade-api",
 *   "redis": "unavailable"
 * }
 */
app.get("/health", async (req, res) => {

    try {

        const redisStatus =
            await redis.ping();

        res.json({
            status: "ok",
            service: "bank-grade-api",
            redis: redisStatus
        });

    } catch (error) {

        res.status(503).json({
            status: "error",
            service: "bank-grade-api",
            redis: "unavailable"
        });

    }

});

/**
 * Endpoint público de ejemplo. No requiere autenticación ni sesión válida.
 * Se utiliza para verificar que la API responde sin necesidad de un
 * Access Token.
 *
 * @name GET/api/public
 * @function
 * @param {import("express").Request} req - Objeto de la petición HTTP.
 * @param {import("express").Response} res - Objeto de la respuesta HTTP.
 * @returns {void} Responde `200 OK` con `{ message: "Public endpoint" }`.
 */
app.get("/api/public", (req, res) => {

    res.json({
        message: "Public endpoint"
    });

});

/**
 * Endpoint protegido de ejemplo. Requiere un Access Token válido y una
 * sesión activa en Redis. La validación es realizada por el middleware
 * {@link module:middleware/auth.middleware.authenticate}.
 *
 * @name GET/api/protected
 * @function
 * @param {import("express").Request} req - Objeto de la petición HTTP.
 *   Contiene `req.auth` con la información del token/sesión, inyectada
 *   por el middleware `authenticate`.
 * @param {import("express").Response} res - Objeto de la respuesta HTTP.
 * @returns {void} Responde `200 OK` con `{ message, user }`, donde `user`
 *   corresponde al contenido de `req.auth`.
 *
 * @middleware authenticate - Verifica la firma del JWT, el issuer, el
 *   audience, la expiración y el estado de la sesión en Redis antes de
 *   permitir el acceso.
 */
app.get(
    "/api/protected",
    authenticate,
    (req, res) => {

        res.json({
            message: "Protected resource",
            user: req.auth
        });

    }
);

/**
 * Inicia el servidor HTTP en el puerto configurado mediante variables de
 * entorno, escuchando en todas las interfaces de red disponibles.
 *
 * @listens env.port
 * @param {number} env.port - Puerto en el que se expone la API.
 * @param {string} "0.0.0.0" - Host de escucha (todas las interfaces).
 * @returns {void}
 */
app.listen(
    env.port,
    "0.0.0.0",
    () => {

        console.log(
            `Bank Grade API running on port ${env.port}`
        );

    }
);