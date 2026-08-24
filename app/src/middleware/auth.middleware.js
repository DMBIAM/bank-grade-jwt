/**
 * @file auth.middleware.js
 * @description Middleware de autenticación y autorización para rutas
 * protegidas. Verifica la firma, el issuer, el audience y la expiración
 * del Access Token (JWT) y, adicionalmente, valida contra Redis que la
 * sesión asociada siga activa y que sus claims coincidan con los datos
 * almacenados. Esta doble verificación (firma + sesión) es el núcleo del
 * enfoque "bank-grade" descrito en el README del proyecto.
 *
 * @module middleware/auth.middleware
 * @requires jsonwebtoken
 * @requires ../config/env.js
 * @requires ../services/session.service.js
 */

import jwt from "jsonwebtoken";

import { env } from "../config/env.js";
import { sessionService } from "../services/session.service.js";

/**
 * Información de autenticación inyectada en `req.auth` cuando el
 * middleware {@link authenticate} valida la petición correctamente.
 *
 * @typedef {Object} AuthContext
 * @property {string} userId - Identificador del usuario (claim `sub` del JWT).
 * @property {string} sessionId - Identificador de la sesión (claim `sid` del JWT).
 * @property {string} jti - Identificador del Access Token vigente.
 * @property {string} role - Rol del usuario, obtenido de la sesión en Redis.
 */

/**
 * Middleware de Express que protege rutas exigiendo un Access Token
 * válido y una sesión activa en Redis.
 *
 * Orden de validación:
 * 1. Verifica que exista el header `Authorization`.
 * 2. Verifica que el esquema sea `Bearer` y que incluya un token.
 * 3. Verifica la firma del JWT, el algoritmo (`HS256`), el `issuer`
 *    (`bank-grade-api`) y el `audience` (`bank-grade-client`).
 * 4. Verifica que el payload contenga los claims requeridos: `sub`
 *    (userId), `sid` (sessionId) y `jti`.
 * 5. Consulta la sesión en Redis mediante
 *    {@link module:services/session.service.sessionService.getSession}
 *    y verifica que exista.
 * 6. Verifica que el estado de la sesión sea `"active"` (no revocada).
 * 7. Verifica que `userId` y `jti` de la sesión coincidan con los claims
 *    del token, evitando que un JWT válido pero desincronizado de la
 *    sesión (por ejemplo, tras una rotación) sea aceptado.
 * 8. Si todas las verificaciones pasan, adjunta el contexto de
 *    autenticación en `req.auth` y continúa con `next()`.
 *
 * Esta es la implementación concreta del principio central del proyecto:
 * un JWT criptográficamente válido no es suficiente por sí solo; la
 * sesión asociada también debe seguir siendo válida.
 *
 * @function authenticate
 * @async
 * @param {import("express").Request} req - Objeto de la petición HTTP.
 *   Debe incluir el header `Authorization: Bearer {accessToken}`.
 * @param {import("express").Response} res - Objeto de la respuesta HTTP.
 * @param {import("express").NextFunction} next - Función para continuar
 *   con el siguiente middleware/handler de la cadena.
 *
 * @returns {Promise<void>} No retorna un valor útil directamente; o bien
 *   invoca `next()` dejando `req.auth` disponible como {@link AuthContext}
 *   para los siguientes handlers, o responde con un error HTTP:
 * - `401 Unauthorized` — Falta el header, el formato es inválido, el
 *   token es inválido/expirado, los claims son inválidos, la sesión no
 *   existe, no está activa, o no coincide con los claims del token.
 * - `500 Internal Server Error` — Error inesperado durante la validación
 *   (por ejemplo, falla de conexión con Redis).
 *
 * @example
 * import { authenticate } from "./middleware/auth.middleware.js";
 *
 * app.get("/api/protected", authenticate, (req, res) => {
 *   // req.auth = { userId, sessionId, jti, role }
 *   res.json({ user: req.auth });
 * });
 */
export const authenticate = async (req, res, next) => {

    try {

        const authorization =
            req.headers.authorization;

        if (!authorization) {

            return res.status(401).json({
                error: "Authorization header is required"
            });

        }

        const [scheme, token] =
            authorization.split(" ");

        if (
            scheme !== "Bearer" ||
            !token
        ) {

            return res.status(401).json({
                error: "Invalid authorization format"
            });

        }

        let payload;

        try {

            payload = jwt.verify(
                token,
                env.jwt.secret,
                {
                    algorithms: ["HS256"],
                    issuer: "bank-grade-api",
                    audience: "bank-grade-client"
                }
            );

        } catch (error) {

            return res.status(401).json({
                error: "Invalid or expired token"
            });

        }

        const {
            sub,
            sid,
            jti
        } = payload;

        if (!sub || !sid || !jti) {

            return res.status(401).json({
                error: "Invalid token claims"
            });

        }

        const session =
            await sessionService.getSession(sid);

        if (!session) {

            return res.status(401).json({
                error: "Unauthorized"
            });

        }

        if (session.status !== "active") {

            return res.status(401).json({
                error: "Unauthorized"
            });

        }

        if (
            session.userId !== sub ||
            session.jti !== jti
        ) {

            return res.status(401).json({
                error: "Session validation failed"
            });

        }

        req.auth = {
            userId: sub,
            sessionId: sid,
            jti,
            role: session.role
        };

        next();

    } catch (error) {

        console.error(
            "Authentication middleware error:",
            error
        );

        return res.status(500).json({
            error: "Authentication service error"
        });

    }

};