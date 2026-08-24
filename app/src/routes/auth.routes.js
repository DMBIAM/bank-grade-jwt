/**
 * @file auth.routes.js
 * @description Define las rutas HTTP relacionadas con autenticación:
 * login, logout y renovación de tokens. Este router se monta bajo el
 * prefijo `/api/auth` en {@link module:app}.
 *
 * @module routes/auth.routes
 * @requires express
 * @requires ../controllers/auth.controller.js
 * @requires ../middleware/auth.middleware.js
 */

import { Router } from "express";

import { authController } from "../controllers/auth.controller.js";
import { authenticate } from "../middleware/auth.middleware.js";

/**
 * Instancia de router de Express para los endpoints de autenticación.
 * @constant
 * @type {import("express").Router}
 */
const router = Router();

/**
 * Autentica a un usuario con `username` y `password` y, si son válidos,
 * crea una sesión en Redis y emite un Access Token y un Refresh Token.
 *
 * No requiere autenticación previa.
 *
 * @name POST/api/auth/login
 * @function
 * @see module:controllers/auth.controller.authController.login
 */
router.post(
    "/login",
    authController.login
);

/**
 * Cierra la sesión del usuario autenticado, revocando o eliminando la
 * sesión correspondiente en Redis.
 *
 * Requiere un Access Token válido y una sesión activa, validados por el
 * middleware {@link module:middleware/auth.middleware.authenticate}.
 *
 * @name POST/api/auth/logout
 * @function
 * @middleware authenticate
 * @see module:controllers/auth.controller.authController.logout
 */
router.post(
    "/logout",
    authenticate,
    authController.logout
);

/**
 * Renueva el Access Token a partir de un Refresh Token vigente,
 * ejecutando la rotación atómica del Refresh Token y la detección de
 * reutilización descritas en
 * {@link module:services/auth.service.authService.refresh}.
 *
 * No requiere Access Token; la autorización se realiza mediante el
 * Refresh Token enviado en el cuerpo de la petición.
 *
 * @name POST/api/auth/refresh
 * @function
 * @see module:controllers/auth.controller.authController.refresh
 */
router.post(
    "/refresh",
    authController.refresh
);

export default router;