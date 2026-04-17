import { Router, Request, Response, NextFunction } from 'express'
import authenticate from '../../../middlewares/authenticate'
import { IAuthenticateRequest } from '../../../types/types'

const router = Router()

router.get(
    '/protected',
    (req: Request, res: Response, next: NextFunction) => {
        void authenticate(req, res, next)
    },
    (req: Request, res: Response) => {
        const userReq = req as IAuthenticateRequest

        return res.status(200).json({
            success: true,
            message: 'You are inside a protected route',
            user: userReq.authenticatedUser
        })
    }
)

export default router