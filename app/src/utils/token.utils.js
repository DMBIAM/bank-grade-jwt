/**
 * @file token.utils.js
 * @description Utilidades criptográficas relacionadas con el manejo de
 * tokens. Actualmente provee la función de hashing utilizada para no
 * almacenar Refresh Tokens en texto plano dentro de Redis.
 *
 * @module utils/token.utils
 * @requires node:crypto
 */

import crypto from "node:crypto";

/**
 * Genera el hash SHA-256 de un token en formato hexadecimal.
 *
 * Se utiliza para almacenar en Redis una representación irreversible del
 * Refresh Token (`refreshTokenHash`) en lugar del token real, de modo que
 * un acceso no autorizado a Redis no exponga el secreto original.
 *
 * @function hashToken
 * @param {string} token - Token en texto plano a hashear (por ejemplo,
 *   un Refresh Token).
 * @returns {string} Hash SHA-256 del token, representado como una cadena
 *   hexadecimal de 64 caracteres.
 *
 * @example
 * const hash = hashToken("mi-refresh-token-secreto");
 * // "3f786850e387550fdab836ed7e6dc881de23001b..."
 *
 * @see module:services/session.service - Consume esta función para
 *   comparar y almacenar el hash del Refresh Token en cada sesión.
 */
export const hashToken = (token) => {

    return crypto
        .createHash("sha256")
        .update(token)
        .digest("hex");

};