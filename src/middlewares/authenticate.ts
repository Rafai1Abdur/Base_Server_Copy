import { NextFunction, Request, Response } from 'express'
import { IAuthenticateRequest, IDecryptedJwt } from '../types/types'
import jwt from '../utils/jwt'
import config from '../config/config'
import query from '../APIs/user/_shared/repo/user.repository'
import httpError from '../handlers/errorHandler/httpError'
import responseMessage from '../constant/responseMessage'
import asyncHandler from '../handlers/async'

export default asyncHandler(async (request: Request, _response: Response, next: NextFunction) => {
    try {
        const req = request as IAuthenticateRequest

        const authHeader = req.headers.authorization

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return httpError(next, new Error(responseMessage.UNAUTHORIZED), request, 401)
        }

        const accessToken = authHeader.split(' ')[1]

        const { userId } = jwt.verifyToken(
            accessToken,
            config.TOKENS.ACCESS.SECRET
        ) as IDecryptedJwt

        const user = await query.findUserById(userId)

        if (!user) {
            return httpError(next, new Error(responseMessage.UNAUTHORIZED), request, 401)
        }

        req.authenticatedUser = user
        return next()

    } catch (error: unknown) {

        const err = error as { name?: string }

        if (err.name === 'TokenExpiredError') {
            return httpError(next, new Error('Token expired'), request, 401)
        }

        if (err.name === 'JsonWebTokenError') {
            return httpError(next, new Error('Invalid token'), request, 401)
        }

        return httpError(next, new Error(responseMessage.UNAUTHORIZED), request, 401)
    }
})