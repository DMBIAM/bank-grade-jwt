/**
 * @file auth.controller.js
 * @description Controladores HTTP para los endpoints de autenticación.
 * Valida la entrada de cada petición, delega la lógica de negocio en
 * {@link module:services/auth.service.authService} y
 * {@link module:services/session.service.sessionService}, y traduce sus
 * resultados a respuestas HTTP apropiadas. Consumido por
 * {@link module:routes/auth.routes}.
 *
 * @module controllers/auth.controller
 * @requires ../services/auth.service.js
 * @requires ../services/session.service.js
 */

import { authService } from "../services/auth.service.js";
import { sessionService } from "../services/session.service.js";

/**
 * Controlador de autenticación. Agrupa los handlers de Express para
 * login, logout y renovación de tokens.
 *
 * @namespace authController
 */
export const authController = {

    /**
     * Maneja `POST /api/auth/login`. Valida que se envíen `username` y
     * `password`, delega la verificación de credenciales y la creación
     * de la sesión en {@link module:services/auth.service.authService.login},
     * y responde con el par de tokens si la autenticación es exitosa.
     *
     * @memberof authController
     * @async
     * @function login
     * @param {import("express").Request} req - Petición HTTP. Debe incluir
     *   en `req.body` las propiedades `username` y `password`.
     * @param {import("express").Response} res - Respuesta HTTP.
     *
     * @returns {Promise<void>} Responde con:
     * - `200 OK` y `{ accessToken, refreshToken, tokenType, expiresIn }`
     *   si las credenciales son válidas.
     * - `400 Bad Request` si falta `username` o `password`.
     * - `401 Unauthorized` si las credenciales son inválidas.
     * - `500 Internal Server Error` ante un error inesperado.
     *
     * @example
     * // POST /api/auth/login
     * // Body: { "username": "demo@bank.local", "password": "BankDemo123!" }
     * //
     * // 200 OK:
     * // {
     * //   "accessToken": "...",
     * //   "refreshToken": "...",
     * //   "tokenType": "Bearer",
     * //   "expiresIn": "15m"
     * // }
     */
    async login(req, res) {

        try {

            const {
                username,
                password
            } = req.body;

            if (!username || !password) {

                return res.status(400).json({
                    error: "username and password are required"
                });

            }

            const result =
                await authService.login(
                    username,
                    password
                );

            if (!result) {

                return res.status(401).json({
                    error: "Invalid credentials"
                });

            }

            return res.status(200).json(result);

        } catch (error) {

            console.error(
                "Login error:",
                error
            );

            return res.status(500).json({
                error: "Internal server error"
            });

        }

    },


    /**
     * Maneja `POST /api/auth/logout`. Requiere haber pasado por el
     * middleware {@link module:middleware/auth.middleware.authenticate},
     * que inyecta `req.auth.sessionId`. Elimina por completo la sesión
     * correspondiente en Redis mediante
     * {@link module:services/session.service.sessionService.deleteSession}.
     *
     * @memberof authController
     * @async
     * @function logout
     * @param {import("express").Request} req - Petición HTTP. Requiere
     *   `req.auth.sessionId`, inyectado por el middleware `authenticate`.
     * @param {import("express").Response} res - Respuesta HTTP.
     *
     * @returns {Promise<void>} Responde con:
     * - `200 OK` y `{ message: "Session revoked successfully" }` si la
     *   sesión fue eliminada correctamente.
     * - `500 Internal Server Error` ante un error inesperado.
     *
     * @example
     * // POST /api/auth/logout
     * // Header: Authorization: Bearer {accessToken}
     * //
     * // 200 OK:
     * // { "message": "Session revoked successfully" }
     */
    async logout(req, res) {

        try {

            const {
                sessionId
            } = req.auth;

            await sessionService.deleteSession(
                sessionId
            );

            return res.status(200).json({
                message: "Session revoked successfully"
            });

        } catch (error) {

            console.error(
                "Logout error:",
                error
            );

            return res.status(500).json({
                error: "Internal server error"
            });

        }

    },

    /**
     * Maneja `POST /api/auth/refresh`. Valida que se envíe `refreshToken`
     * y delega la rotación atómica en
     * {@link module:services/auth.service.authService.refresh}, traduciendo
     * cada código de error de negocio a una respuesta HTTP `401`.
     *
     * @memberof authController
     * @async
     * @function refresh
     * @param {import("express").Request} req - Petición HTTP. Debe incluir
     *   en `req.body` la propiedad `refreshToken`.
     * @param {import("express").Response} res - Respuesta HTTP.
     *
     * @returns {Promise<void>} Responde con:
     * - `200 OK` y `{ accessToken, refreshToken, tokenType, expiresIn }`
     *   si la rotación fue exitosa.
     * - `400 Bad Request` si falta `refreshToken`.
     * - `401 Unauthorized` con `"Refresh token reuse detected"` si
     *   {@link module:services/auth.service.authService.refresh} retorna
     *   `REFRESH_TOKEN_REUSE_DETECTED`.
     * - `401 Unauthorized` con `"Invalid refresh token"` para cualquier
     *   otro código de error (`INVALID_REFRESH_TOKEN`, `SESSION_NOT_FOUND`,
     *   `SESSION_REVOKED`).
     * - `500 Internal Server Error` ante un error inesperado.
     *
     * @example
     * // POST /api/auth/refresh
     * // Body: { "refreshToken": "..." }
     * //
     * // 200 OK:
     * // {
     * //   "accessToken": "...",
     * //   "refreshToken": "...",
     * //   "tokenType": "Bearer",
     * //   "expiresIn": "15m"
     * // }
     */
    async refresh(req, res) {

        try {

            const {
                refreshToken
            } = req.body;


            if (!refreshToken) {

                return res.status(400).json({
                    error: "refreshToken is required"
                });

            }


            const result =
                await authService.refresh(
                    refreshToken
                );


            if (!result) {

                return res.status(401).json({
                    error: "Unauthorized"
                });

            }


            if (result.error) {

                if (
                    result.error ===
                    "REFRESH_TOKEN_REUSE_DETECTED"
                ) {

                    return res.status(401).json({
                        error: "Refresh token reuse detected"
                    });

                }


                return res.status(401).json({
                    error: "Invalid refresh token"
                });

            }


            return res.status(200).json(result);

        } catch (error) {

            console.error(
                "Refresh token error:",
                error
            );

            return res.status(500).json({
                error: "Internal server error"
            });

        }

    }

};