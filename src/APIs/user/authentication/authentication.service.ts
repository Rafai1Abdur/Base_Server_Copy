import responseMessage from '../../../constant/responseMessage'
import parsers from '../../../utils/parsers'
import { ILoginRequest, IRegisterRequest } from './types/authentication.interface'
import dateAndTime from '../../../utils/date-and-time'
import { CustomError } from '../../../utils/errors'
import query from '../_shared/repo/user.repository'
import hashing from '../../../utils/hashing'
import code from '../../../utils/code'
import { IUser } from '../_shared/types/users.interface'
import { EUserRoles } from '../../../constant/users'
import emailService from '../../../services/email'
import logger from '../../../handlers/logger'
import validate from './validation/validations'
import dayjs from 'dayjs'
import utc from 'dayjs/plugin/utc'
import jwt from '../../../utils/jwt'
import config from '../../../config/config'
import { IToken } from '../_shared/types/token.interface'

// Importing the refreshTokenService to handle token refreshing
import tokenRepository from '../_shared/repo/token.repository'

import { IDecryptedJwt } from '../../../types/types'
// Importing the refreshTokenService to handle token refreshing 

dayjs.extend(utc)

export const registrationService = async (payload: IRegisterRequest) => {
    const { name, phoneNumber, email, password } = payload

    // Parsing and validating phone number
    const { countryCode, internationalNumber, isoCode } = parsers.parsePhoneNumber('+' + phoneNumber)
    if (!countryCode || !internationalNumber || !isoCode) {
        throw new CustomError(responseMessage.auth.INVALID_PHONE_NUMBER, 422)
    }

    // Extracting country timezone
    const timezone = dateAndTime.countryTimezone(isoCode)
    if (!timezone || timezone.length === 0) {
        throw new CustomError(responseMessage.auth.INVALID_PHONE_NUMBER, 422)
    }

    //Validate if user already exists
    await validate.userAlreadyExistsViaEmail(email)

    //Encrypting password
    const hashedPassword = await hashing.hashPassword(password)

    //Account confimation token and code generation
    const token = code.generateRandomId()
    const OTP = code.generateOTP(6)

    const userObj: IUser = {
        name,
        email,
        phoneNumber: {
            countryCode,
            isoCode,
            internationalNumber
        },
        accountConfimation: {
            status: false,
            token,
            code: OTP,
            timestamp: null
        },
        passwordReset: {
            token: null,
            expiry: null,
            lastResetAt: null
        },
        lastLoginAt: null,
        role: EUserRoles.USER,
        timezone: timezone[0].name,
        password: hashedPassword,
        consent: true
    }

    //adding user to db
    const newUser = await query.createUser(userObj)

    //Sending confimation emails
    const confimationURL = `Frontendhost/confimation/${token}?code=${OTP}`
    const to = [email]
    const subject = `Confirm your account`
    const text = `Hey ${name}, Please confirm your account by clicking the link belown\n\n${confimationURL}`

    emailService.sendEmail(to, subject, text).catch((error) => {
        logger.error('Error sending email', {
            // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
            meta: error
        })
    })

    return {
        success: true,
        _id: newUser._id
    }
}

export const accountConfirmationService = async (token: string, code: string) => {
    const user = await query.findUserByConfirmationTokenAndCode(token, code)
    if (!user) {
        throw new CustomError(responseMessage.auth.USER_NOT_EXIST, 404)
    }

    //Check if account is already confirmed
    if (user.accountConfimation.status) {
        throw new CustomError(responseMessage.auth.ALREADY_CONFIRMED('Account'), 400)
    }

    //if not, lets confirm
    user.accountConfimation.status = true
    user.accountConfimation.timestamp = dayjs().utc().toDate()

    await user.save()

    //Sending confimation emails
    const to = [user.email]
    const subject = `Welcome to the base! `
    const text = `Account has been confirmed.`

    emailService.sendEmail(to, subject, text).catch((error) => {
        logger.error('Error sending email', {
            // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
            meta: error
        })
    })

    return {
        success: true,
        _id: user._id
    }
}

export const loginService = async (payload: ILoginRequest) => {
    const { email, password } = payload

    //Check if the user is registered
    const user = await query.findUserByEmail(email, 'password')
    if (!user) {
        throw new CustomError(responseMessage.NOT_FOUND('User'), 404)
    }

    //Validate password
    const isValidPassword = await hashing.comparePassword(password, user.password)
    if (!isValidPassword) {
        throw new CustomError(responseMessage.auth.INVALID_EMAIL_OR_PASSWORD, 400)
    }

    //Genrate tokens
    const accessToken = jwt.generateToken({ userId: user._id }, config.TOKENS.ACCESS.SECRET, config.TOKENS.ACCESS.EXPIRY)
    const refreshToken = jwt.generateToken({ userId: user._id }, config.TOKENS.REFRESH.SECRET, config.TOKENS.REFRESH.EXPIRY)

    user.lastLoginAt = dayjs().utc().toDate()

    await user.save()

    //Storing refresh token into db
    const token: IToken = {
    token: refreshToken,
    // Adding userId to the token object for better tracking and management
    userId: user._id.toString()
    }
    await tokenRepository.createToken(token)

    //delete (user as any).password
    //const { password, ...safeUser } = user.toObject()

    return {
        success: true,
        user: user,
        accessToken: accessToken,
        refreshToken: refreshToken
    }
}

/* 
// NEW FUNCTION ADDED FOR REFRESHING TOKEN
export const refreshTokenService = async (refreshToken: string) => {

    // 1. Verify token signature
    const decoded = jwt.verifyToken(
        refreshToken,
        config.TOKENS.REFRESH.SECRET
    ) as IDecryptedJwt

    // 2. Check if token exists in DB
    const tokenExists = await tokenRepository.findToken(refreshToken)

    if (!tokenExists) {
        throw new CustomError(responseMessage.UNAUTHORIZED, 401)
    }

    // 3. Generate new access token
    const accessToken = jwt.generateToken(
        { userId: decoded.userId },
        config.TOKENS.ACCESS.SECRET,
        config.TOKENS.ACCESS.EXPIRY
    )

    return {
        success: true,
        accessToken
    }
}   */

    // NEW FUNCTION ADDED FOR REFRESHING TOKEN WITH ROTATION (DELETING OLD REFRESH TOKEN AND CREATING NEW ONE)
    export const refreshTokenService = async (refreshToken: string) => {
    // 1. Verify token
    const decoded = jwt.verifyToken(
        refreshToken,
        config.TOKENS.REFRESH.SECRET
    ) as IDecryptedJwt

    // 2. Check if token exists in DB
    const existingToken = await tokenRepository.findToken(refreshToken)

    if (!existingToken) {
        throw new CustomError('Invalid refresh token', 401)
    }

    // 3. DELETE old refresh token (rotation 🔥)
    await tokenRepository.deleteToken(refreshToken)

    // 4. Generate NEW tokens
    const newAccessToken = jwt.generateToken(
        { userId: decoded.userId },
        config.TOKENS.ACCESS.SECRET,
        config.TOKENS.ACCESS.EXPIRY
    )

    const newRefreshToken = jwt.generateToken(
        { userId: decoded.userId },
        config.TOKENS.REFRESH.SECRET,
        config.TOKENS.REFRESH.EXPIRY
    )

    // 5. Store new refresh token in DB
    await tokenRepository.createToken({
        token: newRefreshToken,
        userId: decoded.userId
    })

    return {
        accessToken: newAccessToken,
        refreshToken: newRefreshToken
    }
}