<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;


class AuthController extends Controller
{

    public function register(Request $request)
    {
        // 1. Validar los datos de entrada
        $request->validate([
            'name' => 'required|string|max:255',
            'username' => 'required|string|max:255|unique:users', // username debe ser único en la base de datos users
            'email' => 'required|string|email|max:255|unique:users', // |email|: que el campo sea del tipo email y debe ser único en la bd. users.
            'password' => 'required|string|min:8|confirmed', // confirmed: para que la contraseña y la confirmación sean iguales
        ]);

        // 2. Después que paso la validación podemós crear el nuevo usuario en la base de datos.
        $user = User::create([
            'name' => $request->name,
            'username' => $request->username,
            'email' => $request->email,
            'password' => Hash::make($request->password), // Encriptar la contraseña
        ]);

        // 3.  Crear un token de acceso para el usuario
        //$token = $user->createToken('auth_token')->plainTextToken;

        // 4. Retornar una respuesta exitosa con el token de acceso
        return response()->json([
            'message' => 'Usuario creado correctamente',
            'user' => $user,
            //'token' => $token,
        ], 201); // 201: Created (Código creado correctamente)
    }

    /**
     * Inicia sesión del usuario y genera un token de acceso
     */
    public function login(Request $request)
    {
        // 1. Validar los datos de entrada
        $request->validate([
            'email' => 'required|string|email',
            'password' => 'required|string',
        ]);

        // 2. Intentar autenticar al usuario con las credenciales
        if (!Auth::attempt($request->only('email', 'password'))) {
            return response()->json([
                'message' => 'Credenciales incorrectas'
            ], 401); // 401: Unauthorized (Código de error de autenticación)
        }

        // 3. Obtener el usuario autenticado
        $user = $request->user();

        // 4. Generar un nuevo token de acceso para el usuario
        $token = $user->createToken('auth_token')->plainTextToken;

        // 5. Retornar una respuesta exitosa con el token de acceso y los datos del usuario
        return response()->json([
            'message' => 'Inicio de sesión exitoso',
            'user' => $user,
            'access_token' => $token,
            'token_type' => 'Bearer',
        ]);
    }

    /**
     * Cerrar sesión del usuario y elimina el token de acceso actual
     *
     * @param \Illuminate\Http\Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout(Request $request)
    {
        // 1. Eliminar el token de acceso actual del usuario
        //$request->user()->currentAccessToken()->delete;
        Auth::user()->tokens()->delete();

        // 2. Retornar una respuesta exitosa
        return response()->json([
            'message' => 'Cierre de sesión exitoso'
        ]);
    }

    /**
     * Obtener los datos del usuario autenticado
     *
     * @param \Illuminate\Http\Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function user(Request $request)
    {
        // 1. Obtener los datos del usuario (perfil de usuario) autenticado
        $user = $request->user();

        // 2. Retornar una respuesta exitosa con los datos del usuario
        return response()->json([
            'message' => "Acerca del perfil de usuario.",
            'user' => $user,
        ]);
    }
}


/*
 * Explicación del Código
* register(Request $request):

    * $request->validate(...): Esto es un validador de Laravel. Asegura que los datos recibidos (nombre, email y contraseña) cumplan con ciertas reglas (requerido, formato de email, contraseña de al menos 8 caracteres y confirmación).

    * User::create(...): Crea una nueva instancia del modelo User y la guarda en la base de datos. La contraseña se encripta con Hash::make() para almacenarla de forma segura.

    * $user->createToken('auth_token')->plainTextToken: Aquí es donde entra en juego Sanctum. Genera un token de acceso para el usuario recién creado y nos devuelve la versión en texto plano para que se la enviemos a Angular.

* login(Request $request):

    * Auth::attempt(...): Este método es la forma nativa de Laravel de intentar autenticar a un usuario con sus credenciales. Si el email y la contraseña coinciden con un registro en la base de datos, devuelve true.

    * ValidationException::withMessages(...): Si Auth::attempt falla, lanzamos una excepción para que el frontend sepa que hubo un error de credenciales.

    * $request->user(): Después de una autenticación exitosa, este método devuelve la instancia del modelo User del usuario autenticado.

    * $user->createToken(...): Al igual que en el registro, se crea un nuevo token para la sesión del usuario.

*   logout(Request $request):

    * $request->user()->currentAccessToken()->delete(): Accede al usuario autenticado y elimina el token que está usando actualmente. Esto invalida su sesión y le pide que se vuelva a autenticar para acceder a las rutas protegidas.

* user(Request $request):

    * $request->user(): Simplemente devuelve los datos del usuario que hizo la petición. Esta ruta es útil para que el frontend verifique si un usuario está logueado y obtenga su información.
Con este controlador, tu backend de Laravel ya tiene la lógica completa para manejar la autenticación. Ahora puedes probar estas rutas con una herramienta como Postman para asegurarte de que todo funcione como esperas antes de pasar al frontend en Angular.
*/
