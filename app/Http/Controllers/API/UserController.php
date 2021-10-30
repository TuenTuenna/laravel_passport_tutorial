<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Http\Resources\UserResource;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

class UserController extends Controller
{

    public function fetchUsers(){
        return UserResource::collection(User::all());
    }

    //
    public function currentUserInfo()
    {
        $fetchedUser = new UserResource(Auth::user());
        return response()->json([
           'user' => $fetchedUser
        ], Response::HTTP_OK);
    }
}
