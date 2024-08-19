import User from '@/models/user'
import RefreshToken, {RefreshTokenType} from "@/models/refreshToken";
import bcrypt from 'bcryptjs'
import createHttpError from 'http-errors';
import jwt from 'jsonwebtoken';
import { connect } from '@/dbConfig/dbConfig';
import { NextRequest, NextResponse } from 'next/server';

connect()

export async function POST(req: NextRequest) {
    const data = await req.formData();
    const username = data.get('username')
    const password = data.get('password')

    try {
        const user = await User.findOne({ username: username }).exec()
        if (!user) {
            throw createHttpError(404, "User not found")
        }

        const passwordIsValid = bcrypt.compareSync(
            password as string,
            user.password
        );

        if (!passwordIsValid) {
            throw createHttpError(401, "Unauthorized: Incorrect password")
        }

        const jwtExpiry = process.env.JWT_TOKEN_EXPIRY;
        if (!jwtExpiry) {
            throw new Error("JWT_TOKEN_EXPIRY is not set");
        }

        const token = jwt.sign({ sub : user._id }, process.env.JWT_SECRET!, {
            expiresIn: parseInt(jwtExpiry)
        });

        const refreshTokenToSend = await (RefreshToken as RefreshTokenType).createToken({_id : user._id})

        const cookieOptions = {
            httpOnly: true,
            sameSite: 'lax' as const, // SameSite is set to 'lax' to allow cross-site requests
            path: '/', // Set path to root to be accessible everywhere
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days in milliseconds
        };

        const response = NextResponse.json(
            { success: true, redirectUrl: '/' },
            { status: 200 }
        );

        response.cookies.set('token', token, cookieOptions);
        response.cookies.set('refreshToken', refreshTokenToSend, cookieOptions);

        return response;

    } catch (error) {
        console.error(error);
        // Instead of JSON response, redirect to signin page with error
        const errorUrl = new URL('/signin', req.url);
        errorUrl.searchParams.set('error', error instanceof createHttpError.HttpError ? error.message : 'Internal Server Error');
        return NextResponse.redirect(errorUrl);
    }
}