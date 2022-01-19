import exampleModel from "../models/example.model";
import {Request, Response} from 'express';

export async function getExample(req:Request, res:Response) {
    const id: String = req.params.id;

    const something: any = exampleModel.getSomething(id);
    if (typeof something !== 'undefined'){
        return res.status(200).json({
            something: something,
        });
    } else {
        return res.status(404).json({
            msg: 'Not Found'
        });
    }
}

export async function addExample(req:Request, res:Response) {
    const something: any = req.body.something;

    if (exampleModel.addSomething(something)){
        return res.status(200).json({});
    } else {
        return res.status(400).json({
            msg: 'BAD REQUEST'
        })
    }
}