/**
 * @file auth.service.js
 * @description Lógica principal de autenticación de la arquitectura
 * Bank-Grade JWT. Implementa el login contra las credenciales definidas
 * por variables de entorno, la emisión de Access Token (JWT) y Refresh
 * Token, y la rotación atómica del Refresh Token en cada renovación.
 *
 * @module services/auth.service
 * @requires jsonwebtoken
 * @requires node:crypto
 * @requires ../config/env.js
 * @requires ./session.service.js
 */

import jwt from "jsonwebtoken";
import crypto from "node:crypto";

import { env } from "../config/env.js";
import { sessionService } from "./session.service.js";

/**
 * Resultado exitoso de una operación de login o refresh: contiene el
 * par de tokens vigente y sus metadatos.
 *
 * @typedef {Object} AuthTokens
 * @property {string} accessToken - Access Token (JWT) firmado, de corta duración.
 * @property {string} refreshToken - Refresh Token en texto plano, con el
 *   formato `{sessionId}.{secret}`.
 * @property {"Bearer"} tokenType - Tipo de token, siempre `"Bearer"`.
 * @property {string} expiresIn - Duración del Access Token (por ejemplo, `"15m"`).
 */

/**
 * Resultado de error de una operación de refresh.
 *
 * @typedef {Object} AuthError
 * @property {("INVALID_REFRESH_TOKEN"|"SESSION_NOT_FOUND"|"SESSION_REVOKED"|"REFRESH_TOKEN_REUSE_DETECTED")} error
 *   Código que identifica la causa del fallo.
 */

/**
 * Servicio de autenticación. Orquesta el login, la emisión de tokens y
 * la rotación de Refresh Tokens, delegando el control de estado de
 * sesión a {@link module:services/session.service.sessionService}.
 *
 * @namespace authService
 */
export const authService = {

    /**
     * Autentica a un usuario contra las credenciales estáticas definidas
     * en las variables de entorno y, si son válidas, crea una nueva
     * sesión en Redis y emite el par de tokens (Access + Refresh).
     *
     * Flujo:
     * 1. Valida `username`/`password` contra `env.user`.
     * 2. Genera un `sessionId`, un `jti` para el Access Token y un
     *    Refresh Token compuesto por `{sessionId}.{secretAleatorio}`.
     * 3. Persiste la sesión en Redis mediante
     *    {@link module:services/session.service.sessionService.createSession}.
     * 4. Firma el Access Token (JWT) con los claims `sub`, `sid`, `role`,
     *    `jti`, `iss` y `aud`.
     *
     * @memberof authService
     * @async
     * @function login
     * @param {string} username - Nombre de usuario o correo enviado por el cliente.
     * @param {string} password - Contraseña en texto plano enviada por el cliente.
     *
     * @returns {Promise<AuthTokens|null>} El par de tokens si las
     *   credenciales son válidas, o `null` si no coinciden con las
     *   configuradas en el entorno.
     *
     * @example
     * const result = await authService.login("demo@bank.local", "BankDemo123!");
     * if (!result) {
     *   // Credenciales inválidas
     * }
     */
    async login(username, password) {

        if (
            username !== env.user.username ||
            password !== env.user.password
        ) {

            return null;

        }


        /*
         * ====================================================
         * SESSION ID
         * ====================================================
         */

        const sessionId =
            crypto.randomUUID();


        /*
         * ====================================================
         * ACCESS TOKEN JTI
         * ====================================================
         */

        const jti =
            crypto.randomUUID();


        /*
         * ====================================================
         * REFRESH TOKEN
         * ====================================================
         */

        const refreshSecret =
            crypto.randomBytes(64).toString("hex");


        const refreshToken =
            `${sessionId}.${refreshSecret}`;


        /*
         * ====================================================
         * CREATE SESSION
         * ====================================================
         */

        await sessionService.createSession({

            sessionId,

            userId:
                env.user.id,

            username:
                env.user.username,

            role:
                env.user.role,

            jti,

            refreshToken

        });


        /*
         * ====================================================
         * ACCESS TOKEN
         * ====================================================
         */

        const accessToken =
            jwt.sign(

                {
                    sub:
                        env.user.id,

                    sid:
                        sessionId,

                    role:
                        env.user.role

                },

                env.jwt.secret,

                {

                    expiresIn:
                        env.jwt.accessExpiresIn,

                    jwtid:
                        jti,

                    issuer:
                        "bank-grade-api",

                    audience:
                        "bank-grade-client"

                }

            );


        return {

            accessToken,

            refreshToken,

            tokenType:
                "Bearer",

            expiresIn:
                env.jwt.accessExpiresIn

        };

    },


    /**
     * Renueva el Access Token a partir de un Refresh Token vigente,
     * ejecutando una rotación atómica en Redis (ver
     * {@link module:services/session.service.sessionService.rotateRefreshToken}).
     *
     * Flujo:
     * 1. Extrae el `sessionId` embebido en el Refresh Token (formato
     *    `{sessionId}.{secret}`).
     * 2. Consulta la sesión asociada en Redis y valida que exista y
     *    esté activa.
     * 3. Genera un nuevo `jti`, `refreshTokenId` y Refresh Token.
     * 4. Delega en Redis la validación de coincidencia del hash y la
     *    rotación atómica, interpretando el código numérico de retorno.
     * 5. Si la rotación es exitosa, firma un nuevo Access Token.
     *
     * @memberof authService
     * @async
     * @function refresh
     * @param {string} refreshToken - Refresh Token en texto plano enviado
     *   por el cliente, con el formato `{sessionId}.{secret}`.
     *
     * @returns {Promise<AuthTokens|AuthError>} El nuevo par de tokens si
     *   la rotación fue exitosa, o un objeto `{ error }` con el motivo
     *   del rechazo:
     * - `INVALID_REFRESH_TOKEN` — El token no fue enviado o no tiene el
     *   formato esperado (`{sessionId}.{secret}`).
     * - `SESSION_NOT_FOUND` — No existe una sesión asociada al `sessionId`
     *   extraído del token.
     * - `SESSION_REVOKED` — La sesión existe pero ya no está activa.
     * - `REFRESH_TOKEN_REUSE_DETECTED` — El hash del token recibido no
     *   coincide con el almacenado; la sesión fue revocada
     *   automáticamente como medida de seguridad.
     *
     * @example
     * const result = await authService.refresh(refreshToken);
     *
     * if (result.error) {
     *   // Manejar el código de error correspondiente
     * } else {
     *   const { accessToken, refreshToken } = result;
     * }
     */
    async refresh(refreshToken) {

        if (!refreshToken) {

            return {
                error: "INVALID_REFRESH_TOKEN"
            };

        }


        /*
         * ====================================================
         * Extract session ID
         * ====================================================
         */

        const separatorIndex =
            refreshToken.indexOf(".");


        if (separatorIndex === -1) {

            return {
                error: "INVALID_REFRESH_TOKEN"
            };

        }


        const sessionId =
            refreshToken.substring(
                0,
                separatorIndex
            );


        /*
         * ====================================================
         * Get current session
         * ====================================================
         */

        const session =
            await sessionService.getSession(
                sessionId
            );


        if (!session) {

            return {
                error: "SESSION_NOT_FOUND"
            };

        }


        if (session.status !== "active") {

            return {
                error: "SESSION_REVOKED"
            };

        }


        /*
         * ====================================================
         * Generate new credentials
         * ====================================================
         */

        const newJti =
            crypto.randomUUID();


        const newRefreshTokenId =
            crypto.randomUUID();


        const newRefreshSecret =
            crypto.randomBytes(64).toString("hex");


        const newRefreshToken =
            `${sessionId}.${newRefreshSecret}`;


        /*
         * ====================================================
         * ATOMIC ROTATION
         * ====================================================
         */

        const rotationResult =
            await sessionService.rotateRefreshToken({

                sessionId,

                currentRefreshToken:
                    refreshToken,

                newRefreshToken,

                newRefreshTokenId,

                newJti

            });


        /*
         * ====================================================
         * RESULT
         * ====================================================
         */

        if (rotationResult === -2) {

            return {
                error:
                    "REFRESH_TOKEN_REUSE_DETECTED"
            };

        }


        if (rotationResult === -1) {

            return {
                error:
                    "SESSION_REVOKED"
            };

        }


        if (rotationResult === 0) {

            return {
                error:
                    "SESSION_NOT_FOUND"
            };

        }


        /*
         * ====================================================
         * NEW ACCESS TOKEN
         * ====================================================
         */

        const accessToken =
            jwt.sign(

                {
                    sub:
                        session.userId,

                    sid:
                        sessionId,

                    role:
                        session.role

                },

                env.jwt.secret,

                {

                    expiresIn:
                        env.jwt.accessExpiresIn,

                    jwtid:
                        newJti,

                    issuer:
                        "bank-grade-api",

                    audience:
                        "bank-grade-client"

                }

            );


        return {

            accessToken,

            refreshToken:
                newRefreshToken,

            tokenType:
                "Bearer",

            expiresIn:
                env.jwt.accessExpiresIn

        };

    }

};