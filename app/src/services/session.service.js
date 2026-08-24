/**
 * @file session.service.js
 * @description Capa de acceso a Redis encargada del control de sesiones
 * de la arquitectura Bank-Grade JWT. Gestiona la creación, consulta,
 * rotación atómica y eliminación de sesiones, así como la detección de
 * reutilización de Refresh Tokens mediante un script Lua ejecutado
 * directamente en Redis.
 *
 * @module services/session.service
 * @requires ioredis
 * @requires node:crypto
 * @requires ../config/env.js
 * @requires ../utils/token.utils.js
 */

import Redis from "ioredis";
import crypto from "node:crypto";

import { env } from "../config/env.js";
import { hashToken } from "../utils/token.utils.js";

/**
 * Cliente de Redis utilizado exclusivamente por la capa de sesiones.
 * @constant
 * @type {Redis}
 */
const redis = new Redis({
    host: env.redis.host,
    port: env.redis.port
});

/**
 * Prefijo utilizado para todas las claves de sesión almacenadas en Redis.
 * La clave final tiene la forma `session:{sessionId}`.
 *
 * @constant
 * @type {string}
 * @default "session:"
 */
const SESSION_PREFIX = "session:";

/**
 * Tiempo de vida (TTL) de una sesión en segundos. Equivale a 30 días.
 * Pasado este tiempo, Redis elimina automáticamente la clave de sesión.
 *
 * @constant
 * @type {number}
 * @default 2592000
 */
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 30;

/**
 * Script Lua ejecutado de forma atómica por Redis para rotar un Refresh
 * Token sin incurrir en condiciones de carrera.
 *
 * El script realiza, en una sola operación indivisible:
 * 1. Obtiene el `status` de la sesión.
 * 2. Verifica que la sesión exista.
 * 3. Verifica que la sesión esté activa (`status === "active"`).
 * 4. Compara el hash del Refresh Token recibido contra el almacenado.
 * 5. Si no coincide, marca la sesión como `revoked` (posible reutilización
 *    o compromiso del token) y retorna `-2`.
 * 6. Si coincide, actualiza `refreshTokenHash`, `refreshTokenId` y `jti`.
 *
 * @constant
 * @type {string}
 *
 * @description Contrato de KEYS y ARGV esperado por el script:
 * - `KEYS[1]` — Clave de la sesión, con el formato `session:{sid}`.
 * - `ARGV[1]` — Hash del Refresh Token actual (el que el cliente envió).
 * - `ARGV[2]` — Hash del nuevo Refresh Token a almacenar.
 * - `ARGV[3]` — Nuevo `refreshTokenId`.
 * - `ARGV[4]` — Nuevo `jti` (identificador del Access Token).
 *
 * @returns {number} Valor de retorno del script (mapeado por
 *   {@link sessionService.rotateRefreshToken}):
 * - `1` — Rotación exitosa.
 * - `0` — La sesión no existe.
 * - `-1` — La sesión ya estaba revocada.
 * - `-2` — Reutilización de Refresh Token detectada (la sesión queda revocada).
 */
const ROTATE_REFRESH_TOKEN_SCRIPT = `
local sessionKey = KEYS[1]

local currentHash = ARGV[1]
local newHash = ARGV[2]
local newRefreshTokenId = ARGV[3]
local newJti = ARGV[4]

local status = redis.call(
    "HGET",
    sessionKey,
    "status"
)

-- Session does not exist
if not status then
    return 0
end

-- Session already revoked
if status ~= "active" then
    return -1
end

local storedHash = redis.call(
    "HGET",
    sessionKey,
    "refreshTokenHash"
)

-- Refresh token does not match
if storedHash ~= currentHash then

    -- Possible token reuse / compromise
    redis.call(
        "HSET",
        sessionKey,
        "status",
        "revoked"
    )

    return -2

end

-- Rotate refresh token and access token reference
redis.call(
    "HSET",
    sessionKey,

    "refreshTokenHash",
    newHash,

    "refreshTokenId",
    newRefreshTokenId,

    "jti",
    newJti
)

return 1
`;


/**
 * Registra el script Lua en la instancia de ioredis como un comando
 * personalizado: `redis.rotateRefreshToken(...)`.
 *
 * A partir de este punto, invocar `redis.rotateRefreshToken(key, ...argv)`
 * ejecuta {@link ROTATE_REFRESH_TOKEN_SCRIPT} de forma atómica en el
 * servidor de Redis.
 *
 * @see https://github.com/redis/ioredis#lua-scripting ioredis - Lua scripting
 */
redis.defineCommand(
    "rotateRefreshToken",
    {
        numberOfKeys: 1,
        lua: ROTATE_REFRESH_TOKEN_SCRIPT
    }
);


/**
 * Objeto de datos que representa una sesión almacenada en Redis
 * (estructura `hash`).
 *
 * @typedef {Object} SessionRecord
 * @property {string} userId - Identificador único del usuario.
 * @property {string} username - Nombre de usuario o correo del usuario.
 * @property {string} role - Rol asignado al usuario (por ejemplo, "customer").
 * @property {string} jti - Identificador del Access Token vigente.
 * @property {string} refreshTokenId - Identificador del Refresh Token vigente.
 * @property {string} refreshTokenHash - Hash SHA-256 del Refresh Token vigente.
 * @property {("active"|"revoked")} status - Estado actual de la sesión.
 * @property {string} createdAt - Fecha de creación en formato ISO 8601.
 */

/**
 * Servicio de sesiones. Encapsula toda la interacción con Redis
 * relacionada con el ciclo de vida de una sesión: creación, consulta,
 * rotación atómica del Refresh Token y eliminación.
 *
 * @namespace sessionService
 */
export const sessionService = {


    /**
     * Crea una nueva sesión en Redis asociada a un usuario autenticado.
     *
     * Genera un `refreshTokenId` único, calcula el hash del Refresh Token
     * recibido (nunca se almacena en texto plano) y persiste la sesión
     * como un hash de Redis con un TTL de {@link SESSION_TTL_SECONDS}.
     *
     * @memberof sessionService
     * @async
     * @function createSession
     * @param {Object} params - Datos necesarios para crear la sesión.
     * @param {string} params.sessionId - Identificador único de la sesión (`sid`).
     * @param {string} params.userId - Identificador único del usuario.
     * @param {string} params.username - Nombre de usuario o correo.
     * @param {string} params.role - Rol del usuario.
     * @param {string} params.jti - Identificador del Access Token emitido.
     * @param {string} params.refreshToken - Refresh Token en texto plano
     *   (se hashea antes de almacenarse; nunca se persiste directamente).
     *
     * @returns {Promise<{sessionId: string, refreshTokenId: string}>}
     *   Identificadores de la sesión creada y del Refresh Token asociado.
     *
     * @example
     * const { sessionId, refreshTokenId } = await sessionService.createSession({
     *   sessionId: "995455d8-986e-4137-8b8b-72afa77e1e94",
     *   userId: "user-001",
     *   username: "demo@bank.local",
     *   role: "customer",
     *   jti: "82fda408-...",
     *   refreshToken: "refresh-token-en-texto-plano"
     * });
     */
    async createSession({
        sessionId,
        userId,
        username,
        role,
        jti,
        refreshToken
    }) {

        const refreshTokenId =
            crypto.randomUUID();

        const sessionKey =
            `${SESSION_PREFIX}${sessionId}`;

        const refreshTokenHash =
            hashToken(refreshToken);


        await redis.hset(
            sessionKey,

            "userId",
            userId,

            "username",
            username,

            "role",
            role,

            "jti",
            jti,

            "refreshTokenId",
            refreshTokenId,

            "refreshTokenHash",
            refreshTokenHash,

            "status",
            "active",

            "createdAt",
            new Date().toISOString()
        );


        await redis.expire(
            sessionKey,
            SESSION_TTL_SECONDS
        );


        return {
            sessionId,
            refreshTokenId
        };

    },


    /**
     * Obtiene los datos completos de una sesión almacenada en Redis.
     *
     * @memberof sessionService
     * @async
     * @function getSession
     * @param {string} sessionId - Identificador de la sesión a consultar.
     * @returns {Promise<SessionRecord|null>} El registro de la sesión si
     *   existe, o `null` si la sesión no existe o ya expiró.
     *
     * @example
     * const session = await sessionService.getSession("995455d8-...");
     * if (!session) {
     *   // La sesión no existe o expiró
     * }
     */
    async getSession(sessionId) {

        const sessionKey =
            `${SESSION_PREFIX}${sessionId}`;


        const session =
            await redis.hgetall(sessionKey);


        if (
            !session ||
            Object.keys(session).length === 0
        ) {

            return null;

        }


        return session;

    },


    /**
     * Rota el Refresh Token de una sesión de forma atómica, delegando la
     * validación completa (existencia, estado activo, coincidencia de hash
     * y actualización) al script Lua {@link ROTATE_REFRESH_TOKEN_SCRIPT}
     * ejecutado directamente en Redis.
     *
     * Este método es el punto central de la detección de reutilización
     * (Reuse Detection): si el hash recibido no coincide con el almacenado,
     * la sesión se revoca automáticamente dentro del propio script.
     *
     * @memberof sessionService
     * @async
     * @function rotateRefreshToken
     * @param {Object} params - Parámetros de la rotación.
     * @param {string} params.sessionId - Identificador de la sesión.
     * @param {string} params.currentRefreshToken - Refresh Token actual
     *   en texto plano, enviado por el cliente.
     * @param {string} params.newRefreshToken - Nuevo Refresh Token en
     *   texto plano a emitir si la rotación es exitosa.
     * @param {string} params.newRefreshTokenId - Identificador del nuevo
     *   Refresh Token.
     * @param {string} params.newJti - Nuevo identificador (`jti`) para el
     *   próximo Access Token.
     *
     * @returns {Promise<number>} Resultado de la operación atómica:
     * - `1` — Rotación exitosa.
     * - `0` — La sesión no existe.
     * - `-1` — La sesión ya estaba revocada.
     * - `-2` — Reutilización de Refresh Token detectada; la sesión fue
     *   revocada como medida de seguridad.
     *
     * @example
     * const result = await sessionService.rotateRefreshToken({
     *   sessionId: "995455d8-...",
     *   currentRefreshToken: "token-actual",
     *   newRefreshToken: "token-nuevo",
     *   newRefreshTokenId: crypto.randomUUID(),
     *   newJti: crypto.randomUUID()
     * });
     *
     * if (result === -2) {
     *   // Posible compromiso del token: la sesión ya fue revocada
     * }
     */
    async rotateRefreshToken({
        sessionId,
        currentRefreshToken,
        newRefreshToken,
        newRefreshTokenId,
        newJti
    }) {

        const sessionKey =
            `${SESSION_PREFIX}${sessionId}`;


        const currentHash =
            hashToken(currentRefreshToken);


        const newHash =
            hashToken(newRefreshToken);


        const result =
            await redis.rotateRefreshToken(
                sessionKey,
                currentHash,
                newHash,
                newRefreshTokenId,
                newJti
            );


        return result;

    },


    /**
     * Elimina por completo una sesión de Redis (logout o revocación
     * definitiva). A diferencia de marcar `status: "revoked"`, esta
     * operación borra la clave por completo.
     *
     * @memberof sessionService
     * @async
     * @function deleteSession
     * @param {string} sessionId - Identificador de la sesión a eliminar.
     * @returns {Promise<void>}
     *
     * @example
     * await sessionService.deleteSession("995455d8-986e-4137-8b8b-72afa77e1e94");
     */
    async deleteSession(sessionId) {

        const sessionKey =
            `${SESSION_PREFIX}${sessionId}`;


        await redis.del(sessionKey);

    }

};