<?php

namespace App\API\Common\V1;

use App\API\BaseApi;
use App\DTO\LoginDto;
use App\Factory\AppUserFactory;
use App\Repository\AppUserRepository;
use App\Repository\RefreshTokenRepository;
use App\Service\AppUserProvider;
use Doctrine\ORM\EntityManagerInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Attribute\MapRequestPayload;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Symfony\Contracts\Translation\TranslatorInterface;

class AuthApi extends BaseApi
{
    private AppUserRepository $appUserRepository;
    private RefreshTokenRepository $refreshTokenRepository;
    private AppUserFactory $appUserFactory;
    private UserPasswordHasherInterface $passwordHasher;
    private JWTTokenManagerInterface $tokenManager;

    private TranslatorInterface $translator;

    public function __construct(
        EntityManagerInterface $orm,
        ValidatorInterface $validator,
        AppUserProvider $appUserProvider,
        AppUserRepository $appUserRepository,
        RefreshTokenRepository $refreshTokenRepository,
        AppUserFactory $appUserFactory,
        UserPasswordHasherInterface $passwordHasher,
        JWTTokenManagerInterface $tokenManager,
        TranslatorInterface $translator
    )
    {
        parent::__construct($orm, $validator, $appUserProvider);

        $this->appUserRepository = $appUserRepository;
        $this->refreshTokenRepository = $refreshTokenRepository;
        $this->appUserFactory = $appUserFactory;
        $this->passwordHasher = $passwordHasher;
        $this->tokenManager = $tokenManager;

        $this->translator = $translator;
    }

    #[Route('/auth/register/', name: 'api-v1-auth-register', methods: [ 'POST' ])]
    public function register(Request $request): JsonResponse
    {
        $firstName = $request->get('first_name');
        $lastName = $request->get('last_name');
        $email = $request->get('email');
        $password = $request->get('password');
        $passwordConfirmation = $request->get('password_confirmation');

        if (is_null($firstName)) {
            return $this->errorJsonResponse('Bitte gib deinen Vornamen ein');
        }

        if (is_null($lastName)) {
            return $this->errorJsonResponse('Bitte gib deinen Nachnamen ein');
        }

        if (is_null($email) || strlen($email) == 0) {
            return $this->errorJsonResponse('Bitte gib deine Email-Adresse ein');
        }

        if (is_null($password) || strlen($password) == 0) {
            return $this->errorJsonResponse('Bitte gib dein Passwort ein');
        }

        if (is_null($passwordConfirmation) || strlen($passwordConfirmation) == 0) {
            return $this->errorJsonResponse('Bitte gib die Bestätigung für dein Passwort ein');
        }

        if ($this->appUserRepository->doesEmailAddressAlreadyExist($email)) {
            return $this->errorJsonResponse('Diese Email-Adresse wird bereits verwendet');
        }

        if (!$this->isEmailAddressValid($email)) {
            return $this->errorJsonResponse('Bitte gib eine gültige Email-Adresse an');
        }

        if (!$this->isPasswordStrongEnough($password)) {
            return $this->errorJsonResponse('Bitte gib ein Passwort mit einer Länge von mindestens 8 Zeichen, einem Kleinbuchstaben, einem Großbuchstaben, einer Zahl und einem Sonderzeichen ein');
        }

        if ($password != $passwordConfirmation) {
            return $this->errorJsonResponse('Dein Passwort stimmt nicht mit der Passwortbestätigung überein');
        }

        $appUser = $this->appUserFactory->createOrUpdate($request);
        $appUser->setPassword($this->passwordHasher->hashPassword($appUser, $password));

        $this->orm->persist($appUser);
        $this->orm->flush();

        return $this->json([
            'success' => true,
        ]);
    }

    #[Route('/auth/login/', name: 'api-v1-auth-login', methods: [ 'POST' ])]
    public function login(#[MapRequestPayload] LoginDto $dto): JsonResponse
    {
        $appUser = null;

        if ($dto->type == 'password') {
            $appUser = $this->appUserRepository->findAppUserByEmailAddress(trim($dto->email));

            if (is_null($appUser)) {
                return $this->errorJsonResponse('Es wurde kein Account mit dieser Email-Adresse gefunden');
            }

            if (!$this->passwordHasher->isPasswordValid($appUser, $dto->password)) {
                return $this->errorJsonResponse('Dieses Passwort ist nicht korrekt');
            }
        }

        if ($dto->type == 'refresh_token') {
            $refreshToken = $this->refreshTokenRepository->findByToken($dto->refreshToken);

            if (is_null($refreshToken) || !$refreshToken->isValid()) {
                return $this->unauthorized();
            }

            $appUser = $refreshToken->getAppUser();
            if (is_null($appUser) || $appUser->isLocked()) {
                return $this->unauthorized();
            }

            $refreshToken->setActive(false);
            $this->orm->persist($refreshToken);
        }

        if (is_null($appUser)) {
            return $this->errorJsonResponse('Dieser Account wurde nicht gefunden', 404);
        }

        $accessToken = $this->tokenManager->createFromPayload(
            user: $appUser,
            payload: [
                'user_id' => $appUser->getId(),
                'type' => 'access_token'
            ]
        );

        $refreshToken = $this->refreshTokenRepository->generateRefreshToken($appUser);

        $this->orm->flush();

        return $this->json([
            'access_token' => $accessToken,
            'refresh_token' => $refreshToken,
            'expiration_time' => $this->tokenManager->parse($accessToken)['exp'] * 1000
        ]);
    }

    #[Route('/auth/password/change/', name: 'api-v1-auth-reset-password', methods: [ 'POST' ])]
    public function resetPassword(Request $request): JsonResponse
    {
        $appUser = $this->getAppUser($request);

        if (is_null($appUser)) {
            return $this->unauthorized();
        }

        $password = $request->get('password');
        $newPassword = $request->get('new_password');
        $newPasswordConfirmation = $request->get('new_password_confirmation');

        if (is_null($password) || strlen($password) == 0) {
            return $this->errorJsonResponse('Bitte gib dein aktuelles Passwort ein');
        }

        if (is_null($newPassword) || strlen($newPassword) == 0) {
            return $this->errorJsonResponse('Bitte gib dein neues Passwort ein');
        }

        if (is_null($newPasswordConfirmation) || strlen($newPasswordConfirmation) == 0) {
            return $this->errorJsonResponse('Bitte gib die Bestätitgung für dein neues Password ein');
        }

        if (!$this->passwordHasher->isPasswordValid($appUser, $password)) {
            return $this->errorJsonResponse('Dein altes Passwort ist nicht korrekt');
        }

        if (!$this->isPasswordStrongEnough($newPassword)) {
            return $this->errorJsonResponse('Bitte gib ein neues Passwort mit einer Länge von mindestens 8 Zeichen, einem Kleinbuchstaben, einem Großbuchstaben, einer Zahl und einem Sonderzeichen ein');
        }

        if ($newPassword != $newPasswordConfirmation) {
            return $this->errorJsonResponse('Dein neues Passwort stimmt nicht mit der Passwortbestätigung überein');
        }

        $appUser->setPassword($this->passwordHasher->hashPassword($appUser, $newPassword));
        $this->orm->persist($appUser);
        $this->orm->flush();

        return $this->json([
            'success' => true
        ]);
    }

}