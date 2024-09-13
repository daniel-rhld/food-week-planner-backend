<?php

namespace App\EventListener;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;
use Symfony\Component\HttpKernel\Exception\UnprocessableEntityHttpException;
use Symfony\Component\Validator\Exception\ValidationFailedException;

class ValidationExceptionListener
{
    public function onKernelException(ExceptionEvent $event): void
    {
        $exception = $event->getThrowable();

        if ($exception instanceof UnprocessableEntityHttpException) {
            $validationException = $exception->getPrevious();

            if ($validationException instanceof ValidationFailedException) {
                $violations = $validationException->getViolations();

                if (!is_null($violations) && $violations->count() >= 1) {
                    $violation = $violations->get(0)->getMessage();

                    if (!is_null($violation) && strlen($violation) >= 1) {
                        $event->setResponse(
                            response: new JsonResponse(
                                data: [
                                    'error' => true,
                                    'reason' => $violation
                                ]
                            )
                        );
                    }
                }
            }
        }
    }
}