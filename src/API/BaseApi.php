<?php

namespace App\API;

use App\Entity\AppUser;
use App\Service\AppUserProvider;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Validator\Constraints\Email as EmailConstraints;
use Symfony\Component\Validator\Constraints\Length as LengthConstraints;
use Symfony\Component\Validator\Constraints\Regex as RegexConstraints;
use Symfony\Component\Validator\ConstraintViolationListInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;

class BaseApi extends AbstractController
{
    public EntityManagerInterface $orm;
    public ValidatorInterface $validator;
    private AppUserProvider $appUserProvider;

    public function __construct(
        EntityManagerInterface $orm,
        ValidatorInterface $validator,
        AppUserProvider $appUserProvider
    )
    {
        $this->orm = $orm;
        $this->validator = $validator;
        $this->appUserProvider = $appUserProvider;
    }

    public function getAppUser(Request $request, bool $throwExceptionWhenUnauthorized = true): ?AppUser
    {
        return $this->appUserProvider->fromRequest(
            request: $request,
            throwExceptionWhenUnauthorized: $throwExceptionWhenUnauthorized
        );
    }

    public function isEmailAddressValid(string $emailAddress): bool
    {
        $constraints = new EmailConstraints();
        $errors = $this->validator->validate($emailAddress, $constraints);

        return $errors->count() == 0;
    }

    public function isPasswordStrongEnough(string $password): bool
    {
        $errors = $this->validator->validate(
            $password,
            [
                new LengthConstraints(
                    min: 8
                ),
                new RegexConstraints(
                    pattern: '/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()\-_=+{};:,<.>]).+$/'
                )
            ]
        );

        return $errors->count() == 0;
    }

    public function errorJsonResponse(string $message, int $status = 400): JsonResponse
    {
        return $this->json(
            data: [
                'success' => false,
                'message' => $message
            ],
            status: $status
        );
    }

    public function validationError(ConstraintViolationListInterface $violations): JsonResponse
    {
        $errors = [];
        foreach ($violations as $violation) {
            $fieldName = $violation->getPropertyPath();

            if (!isset($errors[$fieldName])) {
                $errors[$fieldName] = [];
            }

            $errors[$fieldName][] = $violation->getMessage();
        }

        $response = [];

        foreach ($errors as $fieldName => $violations) {
            $response[] = [
                'field' => $fieldName,
                'errors' => $violations
            ];
        }

        return $this->json([
            'success' => false,
            'errors' => $response
        ], 400);
    }

    public function unauthorized(): JsonResponse
    {
        return self::errorJsonResponse(message: 'Unauthorized', status: 401);
    }

    public function notFound(): JsonResponse
    {
        return self::errorJsonResponse(message: 'Resource wurde nicht gefunden', status: 404);
    }

}