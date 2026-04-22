import { NextFunction, Request, Response } from 'express'
import { IAuthenticateRequest, IDecryptedJwt } from '../types/types'
import jwt from '../utils/jwt'
import config from '../config/config'
import query from '../APIs/user/_shared/repo/user.repository'
import httpError from '../handlers/errorHandler/httpError'
import responseMessage from '../constant/responseMessage'

export default async function authenticate(
    request: Request,
    _response: Response,
    next: NextFunction
) {
    const req = request as IAuthenticateRequest

    // TEST LOGGING TO VERIFY IF MIDDLEWARE IS EXECUTED
    // console.log("🔥 AUTH MIDDLEWARE EXECUTED", req.url)

    try {
        const authHeader = req.headers.authorization

        let accessToken: string | undefined

        // 1. Try header first
        if (authHeader?.startsWith('Bearer ')) {
            accessToken = authHeader.split(' ')[1]
        }        

        // 2. If not found, try cookies
        if (!accessToken && req.cookies?.accessToken) {
            accessToken = req.cookies.accessToken as string
        }

        if (!accessToken) {
            return httpError(next, new Error(responseMessage.UNAUTHORIZED), request, 401)
        }

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

    } catch {
        return httpError(next, new Error('Invalid or expired token'), request, 401)
    }
}