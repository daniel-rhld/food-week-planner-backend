<?php

namespace App\Factory;

use App\Entity\AppUser;
use App\Service\AppUserProvider;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\Request;

class AppUserFactory extends EntityFactory
{
    /**
     * @param Request $request
     * @param $entity ?AppUser
     * @return AppUser
     */
    public function createOrUpdate(Request $request, $entity = null): AppUser
    {
        if (is_null($entity)) {
            $entity = new AppUser();
        }

        $firstName = $request->get('first_name');
        $lastName = $request->get('last_name');
        $emailAddress = $request->get('email');

        if (!is_null($firstName) && strlen($firstName) > 0) {
            $entity->setFirstName($firstName);
        }

        if (!is_null($lastName) && strlen($lastName) > 0) {
            $entity->setLastName($lastName);
        }

        if (!is_null($emailAddress) && strlen($emailAddress) > 0) {
            $entity->setEmail($emailAddress);
        }

        return $entity;
    }

    /**
     * @param AppUser $entity
     * @return AppUser
     */
    public function delete($entity): AppUser
    {
        return $entity;
    }
}