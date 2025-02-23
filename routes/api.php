<?php
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;
use Laravel\Socialite\Facades\Socialite;
use App\Models\User;
use Illuminate\Support\Facades\Auth;


Route::post('/register', [AuthController::class, 'register']);
Route::post('/login', [AuthController::class, 'login']);





Route::middleware('auth:sanctum')->group(function () {
    Route::get('/user', [AuthController::class, 'user']);
    Route::post('/logout', [AuthController::class, 'logout']);
});

Route::middleware(['web'])->group(function () {
    Route::get('/google-auth/redirect', [AuthController::class, 'redirectToGoogle']);
    Route::get('/google-auth/callback', [AuthController::class, 'handleGoogleCallback']);
});

/* 

Route::get('/google-auth/redirect', [AuthController::class, 'redirectToGoogle']);


 
Route::get('/google-auth/callback', function () {
    $googleUser = Socialite::driver('google')()->user();
 
    $user = User::updateOrCreate([
        'google_id' => $googleUser->id,
    ], [
        'name' => $googleUser->name,
        'email' => $googleUser->email,
    ]);
 
    Auth::login($user);
    
 
});
 */