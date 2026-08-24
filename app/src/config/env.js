/**
 * @file env.js
 * @description Centraliza la lectura y validación de las variables de
 * entorno de la aplicación. Falla rápido (fail-fast) al arrancar si
 * falta alguna variable requerida, evitando que la aplicación quede en
 * un estado inconsistente en tiempo de ejecución.
 *
 * @module config/env
 */

/**
 * Lista de nombres de variables de entorno cuya presencia es obligatoria
 * para que la aplicación pueda arrancar de forma segura.
 *
 * @constant
 * @type {string[]}
 */
const requiredEnvironmentVariables = [
    "JWT_SECRET",
    "APP_USER_ID",
    "APP_USERNAME",
    "APP_PASSWORD",
    "APP_ROLE"
];

/**
 * Verificación de arranque (fail-fast): recorre
 * {@link requiredEnvironmentVariables} y lanza una excepción de
 * inmediato si alguna de ellas no está definida en `process.env`.
 *
 * @throws {Error} Si falta alguna variable de entorno requerida, con un
 *   mensaje que indica exactamente cuál falta.
 */
for (const variable of requiredEnvironmentVariables) {

    if (!process.env[variable]) {

        throw new Error(
            `Missing required environment variable: ${variable}`
        );

    }

}

/**
 * Configuración centralizada de la aplicación, derivada de las variables
 * de entorno del proceso. Una vez superada la validación de
 * {@link requiredEnvironmentVariables}, este objeto queda disponible
 * para el resto de los módulos (servicios, middleware, controladores).
 *
 * @constant
 * @namespace env
 * @property {string} nodeEnv - Entorno de ejecución (`NODE_ENV`).
 *   Por defecto `"development"`.
 * @property {number} port - Puerto en el que escucha la API (`PORT`).
 *   Por defecto `3000`.
 * @property {Object} user - Credenciales y datos del usuario de
 *   laboratorio, utilizados por
 *   {@link module:services/auth.service.authService.login}.
 * @property {string} user.id - Identificador del usuario (`APP_USER_ID`).
 * @property {string} user.username - Usuario o correo (`APP_USERNAME`).
 * @property {string} user.password - Contraseña en texto plano
 *   (`APP_PASSWORD`), usada solo con fines de laboratorio.
 * @property {string} user.role - Rol asignado al usuario (`APP_ROLE`).
 * @property {Object} jwt - Configuración relacionada con JWT.
 * @property {string} jwt.secret - Secreto utilizado para firmar y
 *   verificar los Access Tokens (`JWT_SECRET`).
 * @property {string} jwt.accessExpiresIn - Duración del Access Token
 *   (`JWT_ACCESS_EXPIRES_IN`). Por defecto `"15m"`.
 * @property {string} jwt.refreshExpiresIn - Duración de referencia del
 *   Refresh Token (`JWT_REFRESH_EXPIRES_IN`). Por defecto `"30d"`.
 * @property {Object} redis - Configuración de conexión a Redis.
 * @property {string} redis.host - Host de Redis (`REDIS_HOST`). Por
 *   defecto `"localhost"`.
 * @property {number} redis.port - Puerto de Redis (`REDIS_PORT`). Por
 *   defecto `6379`.
 *
 * @example
 * import { env } from "./config/env.js";
 *
 * console.log(env.port); // 3000
 * console.log(env.jwt.accessExpiresIn); // "15m"
 */
export const env = {

    nodeEnv: process.env.NODE_ENV || "development",

    port: Number(process.env.PORT) || 3000,

    user: {
        id: process.env.APP_USER_ID,
        username: process.env.APP_USERNAME,
        password: process.env.APP_PASSWORD,
        role: process.env.APP_ROLE
    },

    jwt: {
        secret: process.env.JWT_SECRET,
        accessExpiresIn:
            process.env.JWT_ACCESS_EXPIRES_IN || "15m",
    
        refreshExpiresIn:
            process.env.JWT_REFRESH_EXPIRES_IN || "30d"
    },

    redis: {
        host: process.env.REDIS_HOST || "localhost",
        port: Number(process.env.REDIS_PORT) || 6379
    }

};