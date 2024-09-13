<?php

namespace App\Service;

use App\Entity\AppUser;
use App\Repository\AppUserRepository;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;

class AppUserProvider
{

    private JWTTokenManagerInterface $tokenHandler;
    private AppUserRepository $appUserRepository;

    public function __construct(
        JWTTokenManagerInterface $tokenHandler,
        AppUserRepository $appUserRepository
    )
    {
        $this->tokenHandler = $tokenHandler;
        $this->appUserRepository = $appUserRepository;
    }

    public function fromRequest(
        Request $request,
        bool $throwExceptionWhenUnauthorized = true
    ): ?AppUser
    {
        // Get the raw token
        $rawToken = $request->headers->get('Authorization');
        $tokenComponents = explode(" ", trim($rawToken));

        // Check if the token is correctly formed
        if (
            !isset($tokenComponents[0])
            || $tokenComponents[0] !== 'Bearer'
            || !isset($tokenComponents[1])
            || strlen(trim($tokenComponents[1])) == 0
        ) {
            if ($throwExceptionWhenUnauthorized) {
                throw new UnauthorizedHttpException('');
            } else {
                return null;
            }
        }

        // Get the included data from the token
        try {
            $accessTokenData = $this->tokenHandler->parse($tokenComponents[1]);
        } catch (\Exception) {
            if ($throwExceptionWhenUnauthorized) {
                throw new UnauthorizedHttpException('');
            } else {
                return null;
            }
        }

        // Check if all necessary components are included in the token
        if (
            !isset($accessTokenData['user_id'])
            || !isset($accessTokenData['exp'])
            || !isset($accessTokenData['type'])
        ) {
            if ($throwExceptionWhenUnauthorized) {
                throw new UnauthorizedHttpException('');
            } else {
                return null;
            }
        }

        // Get the unique user ID and the expiration time from the token
        $userId = (int) $accessTokenData['user_id'];
        $accessTokenExpirationTime = (int) $accessTokenData['exp'];
        $now = (new \DateTimeImmutable())->getTimestamp();

        // Check if the token hasn't already expired
        if ($now > $accessTokenExpirationTime) {
            if ($throwExceptionWhenUnauthorized) {
                throw new UnauthorizedHttpException('');
            } else {
                return null;
            }
        }

        // Get the app user from the database
        $appUser = $this->appUserRepository->findAppUserById($userId);

        // Check if the app user exists
        if (is_null($appUser)) {
            if ($throwExceptionWhenUnauthorized) {
                throw new UnauthorizedHttpException('');
            } else {
                return null;
            }
        }

        return $appUser;
    }
}