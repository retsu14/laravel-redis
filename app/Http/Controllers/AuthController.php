<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function login(Request $request)
    {
        try {
            $credentials = $request->validate([
                'email' => ['required', 'email'],
                'password' => ['required'],
            ]);

            if (! Auth::attempt($credentials)) {
                return response()->json([
                    'message' => 'Invalid credentials',
                ], 401);
            }


            return response()->json([
                'message' => 'Logged In Successfully',
                'user' => Auth::user(),
            ], 200);
        } catch (\Throwable $th) {
            report($th);

            return response()->json([
                'message' => 'Login failed',
                'error' => config('app.debug') ? $th->getMessage() : null,
            ], 500);
        }

    }

    public function register(Request $request)
    {
        try {
            $validated = $request->validate([
                'name' => ['required', 'string', 'max:50'],
                'email' => ['required', 'email', 'unique:users,email'],
                'password' => ['required', 'min:6', 'confirmed'],
            ]);

            $validated['password'] = Hash::make($validated['password']);

            $user = User::create($validated);

            return response()->json([
                'message' => 'Registered Successfully',
                'user' => $user,
            ], 201);
        } catch (\Throwable $th) {
            report($th);

            return response()->json([
                'message' => 'Login failed',
                'error' => config('app.debug') ? $th->getMessage() : null,
            ], 500);

        }

    }

    public function logout(Request $request)
    {
        try {
            Auth::logout();

            $request->session()->invalidate();
            $request->session()->regenerateToken();

            return response()->json([
                'message' => 'Logged out Successfully.',
            ], 200);
        } catch (\Throwable $th) {
            report($th);

            return response()->json([
                'message' => 'Login failed',
                'error' => config('app.debug') ? $th->getMessage() : null,
            ], 500);
        }

    }
}
