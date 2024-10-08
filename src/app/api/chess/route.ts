import createHttpError from 'http-errors';
import { connect } from '@/dbConfig/dbConfig';
import { NextRequest, NextResponse } from 'next/server';
import ChessGameModel from '@/models/chessGame';
import { cookies } from 'next/headers';
import { decode } from 'jsonwebtoken';

connect()

interface ExtendedRequest extends NextRequest {
    id: string
}

export async function POST(req: ExtendedRequest) {
    const newGameFenString = 'rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1'
    const token = cookies().get('token')?.value || null
    console.log("Post called with token:", token)

    try {

        if (typeof token == "string") {
            const payload = decode(token as string)

            const newGameInstance = new ChessGameModel({
                fen: newGameFenString,
                status: 'pending',
                user: payload!.sub
            })

            await newGameInstance.save();

            const response = NextResponse.json(
                { success: true, redirectUrl: `/Ai/${newGameInstance._id}` },
                { status: 200 }
            );
            

            return response
        } else {
            const response = NextResponse.json(
                { success: true, redirectUrl: `/signin` },
                { status: 200 }
            );
            return response
        }

    } catch (error) {
        console.log(error)
        return NextResponse.json({
            error: 'Game not created'
        })
    }
}

export async function GET(req: ExtendedRequest) {
    const { searchParams } = new URL(req.url)
    const gameId = searchParams.get('id')
    try {

        const chessGame = await ChessGameModel.findById(gameId).exec()
        if (chessGame) {
            return NextResponse.json(
                {
                    game: chessGame
                }
            )
        } else {
            return NextResponse.json({
                error: 'Game not found'
            })
        }

    } catch (error) {
        console.log(error)
        return NextResponse.json({
            error: 'Game not found'
        })
    }
}