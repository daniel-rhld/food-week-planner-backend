<?php

namespace App\DTO;

use Symfony\Component\Serializer\Attribute\SerializedName;
use Symfony\Component\Validator\Constraints as Assert;

readonly class LoginDto
{
    public function __construct(
        #[SerializedName('email')]
        #[Assert\When(
            expression: 'this.type == "password"',
            constraints: [
                new Assert\NotBlank(message: '')
            ]
        )]
        public ?string $email,

        #[SerializedName('password')]
        #[Assert\When(
            expression: 'this.type == "password"',
            constraints: [
                new Assert\NotBlank(message: 'Bitte gib dein Passwort ein')
            ]
        )]
        public ?string $password,

        #[SerializedName('refresh_token')]
        #[Assert\When(
            expression: 'this.type == "refresh_token"',
            constraints: [
                new Assert\NotBlank(message: 'Kein Refresh-Token vorhanden')
            ]
        )]
        public ?string $refreshToken,

        #[SerializedName('type')]
        #[Assert\NotBlank(message: 'Ungültiger Login-Typ')]
        #[Assert\Choice(
            options: ['password', 'refresh_token'],
            message: 'Ungültiger Login-Typ'
        )]
        public string $type,
    ) {}
}