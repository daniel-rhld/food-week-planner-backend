<?php

namespace App\API\Common\V1;

use App\API\BaseApi;
use App\Service\AppUserProvider;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Validator\Validator\ValidatorInterface;

class AppUserApi extends BaseApi
{

    public function __construct(
        EntityManagerInterface $orm,
        ValidatorInterface $validator,
        AppUserProvider $appUserProvider
    )
    {
        parent::__construct($orm, $validator, $appUserProvider);
    }

    #[Route('/app-users/me/info/', name: 'api-v1-app-user-info', methods: [ 'GET' ])]
    public function getUserInfo(Request $request): JsonResponse
    {
        $appUser = $this->getAppUser($request);
        return $this->json($appUser->toJson());
    }

}