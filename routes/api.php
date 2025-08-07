<?php

use App\Http\Controllers\Api\AuthController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

// Rutas públicas (sin autenticación)
Route::post('/register', [AuthController::class, 'register']);
Route::post('/login', [AuthController::class, 'login']);


// Rutas protegidas (requieren un token de autenticación)
Route::middleware(['auth:sanctum'])->group(function () {
    Route::get('/user', [AuthController::class, 'user']);
    Route::get('/logout', [AuthController::class, 'logout']);
});




/*
 * Route::post('/register', ...) y Route::post('/login', ...): Estas son rutas públicas. Cualquiera puede acceder a ellas para crear una cuenta o iniciar sesión.
 * Route::middleware('auth:sanctum')->group(...): Esto define un grupo de rutas que están protegidas. Para acceder a ellas, la petición debe incluir un token de autenticación válido, que es lo que Angular enviará después de un inicio de sesión exitoso.

*Route::get('/user', ...): Esta ruta te devuelve la información del usuario que está autenticado en ese momento. Es ideal para verificar si el token funciona.

*Route::post('/logout', ...): Esta ruta cierra la sesión eliminando el token de autenticación del usuario.
*/
