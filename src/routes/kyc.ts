import express from 'express'
import { asyncRoute } from './async-route'
import { validateSchema } from '../schema/'
import {
  KycRequestParams,
  KycSchema,
  PersonalDataAndDocumentsKyc,
  NotImplementedError,
  JwtAuthorizationMiddleware,
} from '../types'
import {
  mockKycStatusResponse,
} from '../mocks/express-response'

export function kycRouter({
  jwtAuthMiddleware,
  clientAuthMiddleware,
}: {
  jwtAuthMiddleware: JwtAuthorizationMiddleware
  clientAuthMiddleware: express.RequestHandler[]
}): express.Router {
  const router = express.Router()

  const kycSchemaRequestParamsValidator = (
    req: express.Request,
    _res: express.Response,
    next: express.NextFunction,
  ) => {
    req.params = validateSchema<KycRequestParams>(
      req.params,
      'KycRequestParamsSchema',
    )
    next()
  }

  router.post(
    '/:kycSchema',
    jwtAuthMiddleware.expirationRequired,
    clientAuthMiddleware,
    kycSchemaRequestParamsValidator,
    asyncRoute(
      async (
        req: express.Request<KycRequestParams>,
        _res: express.Response,
      ) => {
        // Delegate to type-specific handlers after validation provides type guards
        switch (req.params.kycSchema) {
          case KycSchema.PersonalDataAndDocuments:
            const data =validateSchema<PersonalDataAndDocumentsKyc>(
              req.body,
              'PersonalDataAndDocumentsKycSchema',
            )
            _res.send({
               "data":data
              });
            break;
          default:
            throw new Error(`Non-existent KYC schema "${req.params.kycSchema}"`)
        }

        throw new NotImplementedError('POST /kyc/:kycSchema not implemented')
      },
    ),
  )

  router.get(
    '/:kycSchema/status',
    jwtAuthMiddleware.expirationOptional,
    clientAuthMiddleware,
    kycSchemaRequestParamsValidator,
    asyncRoute(
      async (
        _req: express.Request<KycRequestParams>,
        _res: express.Response,
      ) => {
        _res.send(mockKycStatusResponse)
        // throw new NotImplementedError(
        //   'GET /kyc/:kycSchema/status not implemented',
        // )
      },
    ),
  )

  router.delete(
    '/:kycSchema',
    jwtAuthMiddleware.expirationRequired,
    clientAuthMiddleware,
    kycSchemaRequestParamsValidator,
    asyncRoute(
      async (
        _req: express.Request<KycRequestParams>,
        _res: express.Response,
      ) => {
        _res.status(200).send({"data":"Deleted Successfully"});
        //throw new NotImplementedError('DELETE /kyc/:kycSchema not implemented')
      },
    ),
  )

  return router
}
