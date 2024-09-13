<?php

namespace App\Factory;

use App\Entity\AppUser;
use App\Service\AppUserProvider;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\Request;

abstract class EntityFactory
{
    protected EntityManagerInterface $orm;
    private AppUserProvider $appUserProvider;

    public function __construct(EntityManagerInterface $orm, AppUserProvider $appUserProvider)
    {
        $this->orm = $orm;
        $this->appUserProvider = $appUserProvider;
    }

    public abstract function createOrUpdate(Request $request, $entity = null);

    public abstract function delete($entity);

    protected function getAppUser(Request $request, bool $throwExceptionWhenUnauthorized = true): ?AppUser
    {
        return $this->appUserProvider->fromRequest($request, $throwExceptionWhenUnauthorized);
    }
}