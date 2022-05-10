import express from 'express'
import { asyncRoute } from './async-route'
import { validateSchema } from '../schema/'
import {
  QuoteRequestQuery,
  //NotImplementedError,
  JwtAuthorizationMiddleware,
} from '../types'
import {
  mockQuoteResponse,
  mockQuoteErrorResponse,
} from '../mocks/express-response'

export function quoteRouter({
  jwtAuthMiddleware,
  clientAuthMiddleware,
}: {
  jwtAuthMiddleware: JwtAuthorizationMiddleware
  clientAuthMiddleware: express.RequestHandler[]
}): express.Router {
  const router = express.Router()

  router.use(jwtAuthMiddleware.expirationOptional)
  router.use(clientAuthMiddleware)

  router.use(
    (
      req: express.Request,
      _res: express.Response,
      next: express.NextFunction,
    ) => {
      req.query = validateSchema<QuoteRequestQuery>(
        req.query,
        'QuoteRequestQuerySchema',
      )
      next()
    },
  )

  router.get(
    '/in',
    asyncRoute(
      async (
        _req: express.Request<{}, {}, {}, QuoteRequestQuery>,
        _res: express.Response,
      ) => {
        // hard coded response 
        //throw new NotImplementedError('GET /quote/in not implemented')
        if(Object.keys(mockQuoteResponse).length===0)
        _res.send(mockQuoteErrorResponse)

        _res.send(mockQuoteResponse);
      },
    ),
  )

  router.get(
    '/out',
    asyncRoute(
      async (
        _req: express.Request<{}, {}, {}, QuoteRequestQuery>,
        _res: express.Response,
      ) => {
        if(Object.keys(mockQuoteResponse).length===0)
        return _res.send(mockQuoteErrorResponse)
        
        return _res.send(mockQuoteResponse);
        //throw new NotImplementedError('GET /quote/out not implemented')
      },
    ),
  )

  return router
}
