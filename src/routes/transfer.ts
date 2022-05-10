import express from 'express'
import { asyncRoute } from './async-route'
import { validateSchema } from '../schema/'
import {
  TransferRequestBody,
  TransferStatusRequestParams,
  //NotImplementedError,
  JwtAuthorizationMiddleware,
} from '../types'
import {
  mockTransferResponse,
  //mockTransferStatusRequestParams,
  mockTransferStatusResponse
} from '../mocks/express-response'

export function transferRouter({
  jwtAuthMiddleware,
  clientAuthMiddleware,
}: {
  jwtAuthMiddleware: JwtAuthorizationMiddleware
  clientAuthMiddleware: express.RequestHandler[]
}): express.Router {
  const router = express.Router()

  const transferRequestBodyValidator = (
    req: express.Request,
    _res: express.Response,
    next: express.NextFunction,
  ) => {
    req.body = validateSchema<TransferRequestBody>(
      req.body,
      'TransferRequestBodySchema',
    )
    next()
  }

  const transferStatusRequestParamsValidator = (
    req: express.Request,
    _res: express.Response,
    next: express.NextFunction,
  ) => {
    req.params = validateSchema<TransferStatusRequestParams>(
      req.params,
      'TransferStatusRequestParamsSchema',
    )
    next()
  }

  router.post(
    '/in',
    jwtAuthMiddleware.expirationRequired,
    clientAuthMiddleware,
    transferRequestBodyValidator,
    asyncRoute(
      async (
        _req: express.Request<{}, {}, TransferRequestBody>,
        _res: express.Response,
      ) => {
        //throw new NotImplementedError('POST /transfer/in not implemented')
        _res.send(mockTransferResponse)
      },
    ),
  )

  router.post(
    '/out',
    jwtAuthMiddleware.expirationRequired,
    clientAuthMiddleware,
    transferRequestBodyValidator,
    asyncRoute(
      async (
        _req: express.Request<{}, {}, TransferRequestBody>,
        _res: express.Response,
      ) => {
        //throw new NotImplementedError('POST /transfer/out not implemented')
        _res.send(mockTransferResponse)
      },
    ),
  )

  router.get(
    '/:transferId/status',
    jwtAuthMiddleware.expirationOptional,
    clientAuthMiddleware,
    transferStatusRequestParamsValidator,
    asyncRoute(
      async (
        _req: express.Request<TransferStatusRequestParams>,
        _res: express.Response,
      ) => {
        // throw new NotImplementedError(
        //   'GET /transfer/:transferId/status not implemented',
        // )
        _res.send(mockTransferStatusResponse)
      },
    ),
  )

  return router
}
