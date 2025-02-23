<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;
use Laravel\Socialite\Facades\Socialite;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Auth;
use Tymon\JWTAuth\Facades\JWTAuth;


class AuthController extends Controller
{
    public function register(Request $request)
{
    $request->validate([
        'nombres' => 'required|string|max:255',
        'apellido_paterno' => 'required|string|max:255',
        'apellido_materno' => 'required|string|max:255',
        'email' => 'required|email|unique:users,email',
        'password' => 'required|min:8|confirmed',
    ], [
        'nombres.required' => 'El campo nombres es obligatorio.',
        'email.unique' => 'Este correo ya está registrado.',
        'password.min' => 'La contraseña debe tener al menos 8 caracteres.',
    ]);

    // Crear un nuevo usuario
    $user = User::create([
        'first_name' => $request->nombres,
        'last_name' => "{$request->apellido_paterno} {$request->apellido_materno}",
        'email' => $request->email,
        'password' => Hash::make($request->password),
    ]);

    // Generar el token de acceso para el nuevo usuario
    $token = $user->createToken('auth_token')->plainTextToken;

    return response()->json(['message' => 'Usuario registrado con éxito.', 'access_token' => $token], 201);
}

  // Inicio de sesión
  public function login(Request $request)
  {
      $request->validate([
          'email' => 'required|email',
          'password' => 'required',
      ]);

      $user = User::where('email', $request->email)->first();

      if (! $user || ! Hash::check($request->password, $user->password)) {
          throw ValidationException::withMessages([
              'email' => ['Credenciales incorrectas.'],
          ]);
      }

      $token = $user->createToken('auth_token')->plainTextToken;

      return response()->json([
          'access_token' => $token,
          'token_type' => 'Bearer',
      ]);
  }


public function handleGoogleCallback()
{
    try {
        // Obtener el usuario desde Google usando Socialite
        $googleUser = Socialite::driver('google')->stateless()->user();

        // Verificar si el usuario existe o crear uno nuevo con la información de Google
        $user = User::updateOrCreate([
            'google_id' => $googleUser->id,
        ], [
            'first_name' => $googleUser->user['given_name'],
            'last_name' => $googleUser->user['family_name'],
            'email' => $googleUser->email,
            'google_token' => $googleUser->token,
            'google_refresh_token' => $googleUser->refreshToken,
        ]);

        // Generar el token de acceso para la API
        $token = $user->createToken('auth_token')->plainTextToken;

        // Redirigir al frontend con el token en la URL
        return redirect('http://localhost:5173/dashboard?access_token=' . $token);
    } catch (\Exception $e) {
        return response()->json(['error' => 'Error al obtener el callback de Google: ' . $e->getMessage()], 500);
    }
}





    // Cierre de sesión
    public function logout(Request $request)
    {
        $request->user()->currentAccessToken()->delete();
        return response()->json(['message' => 'Sesión cerrada con éxito.']);
    }

    // Obtener usuario autenticado
    public function user(Request $request)
    {
        return response()->json($request->user());
    }

    
    //auth por google
// AuthController.php















    public function redirectToGoogle()
{
    try {
        $url = Socialite::driver('google')->redirect()->getTargetUrl();
        return response()->json(['url' => $url]);
    } catch (\Exception $e) {
        // Mostrar detalles del error
        return response()->json(['error' => 'Error al obtener la URL de redirección: ' . $e->getMessage()], 500);
    }
}


    

}



