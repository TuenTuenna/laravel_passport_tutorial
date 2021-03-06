<?php

namespace App\Http\Resources;

use Illuminate\Http\Resources\Json\JsonResource;

class UserResource extends JsonResource
{
    /**
     * Transform the resource into an array.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return array|\Illuminate\Contracts\Support\Arrayable|\JsonSerializable
     */
    public function toArray($request)
    {
        // https://www.gravatar.com/avatar/205e460b479e2e5b48aec07710c08d50?s=200
        $hash = md5(strtolower(trim($this->email)));
        return [
            'id' => $this->id,
            'name' => $this->name,
            'email' => $this->email,
            'avatar' => "https://www.gravatar.com/avatar/$hash.jpg?s=200&d=robohash"
        ];
    }
}
