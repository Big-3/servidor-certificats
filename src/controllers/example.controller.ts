import {Certificate, createCertificate, addCertificateANDSharedKeysToDB, getByCertificate, getUserDNI, verifySign, challengeRSA, validateChallengeRSA} from "../models/example.model";
import {json, Request, Response} from 'express';
import { RSAPublicKey, SharedKey } from "@big3/ciber-modules";
import * as bigintConversion from "bigint-conversion";
/*
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
*/
function HexRSAPublicKey(userRSAPubKey:RSAPublicKey):any
{
    let HexRSAPublicKey = {
        e:bigintConversion.bigintToHex(userRSAPubKey.getExpE()),
        n:bigintConversion.bigintToHex(userRSAPubKey.getModN())
    }
    return HexRSAPublicKey
}

//Rebem una clau RSA pública i un DNI i retornem un certificat
export async function generateCertificate(req:Request, res:Response) {

    let userRSAPubKey:RSAPublicKey=new RSAPublicKey(bigintConversion.hexToBigint(req.body.RSAPublicKey.e), bigintConversion.hexToBigint(req.body.RSAPublicKey.n))
    let userDNI:string=req.body.DNI

    try
    {
        if (!createCertificate(userRSAPubKey)[0])
        {
            return res.status(400).json({
                msg: 'Error en generar el Certificat'
            })
        }

        let userCertificate:Certificate=createCertificate(userRSAPubKey)[1]     

        let autoritiesPasswordSharedkeys:Promise<SharedKey[]>
        let autoritiesIvSharedkeys:Promise<SharedKey[]>

        if (!addCertificateANDSharedKeysToDB(userCertificate,userDNI))
        {
            return res.status(400).json({
                msg: 'Error en desar el certificat o en generar les claus compartides'
            })
        }

           

        let body = {
            RSAPublicKey:HexRSAPublicKey(userRSAPubKey),
            ServerSignature:bigintConversion.bigintToHex(userCertificate.getServerSignature())
        }

        return res.status(200).json(body)

    }
    catch
    {
        return res.status(500).json({
            msg: 'Error al servidor'
        })

    }
    

}

//Rebem dos conjunts de claus compartides (unes corresponents a la contrassenya i les altres al IV) i un Certificat i retornem el DNI de l'usuari
export async function getUser(req:Request, res:Response) {

    
    let userRSAPubKey:RSAPublicKey=new RSAPublicKey(bigintConversion.hexToBigint(req.body.RSAPublicKey.e), bigintConversion.hexToBigint(req.body.RSAPublicKey.n))
    let userCertificate:Certificate= new Certificate(userRSAPubKey,bigintConversion.hexToBigint(req.body.ServerSignature))
    
    let autority1PasswordSharedKey:SharedKey= new SharedKey(bigintConversion.hexToBigint(req.body.autoritiesPasswordSharedkeys[0].s), Number(bigintConversion.hexToBigint(req.body.autoritiesPasswordSharedkeys[0].Λ)),Number(bigintConversion.hexToBigint(req.body.autoritiesPasswordSharedkeys[0].t)),bigintConversion.hexToBigint(req.body.autoritiesPasswordSharedkeys[0].p))
    let autority2PasswordSharedKey:SharedKey= new SharedKey(bigintConversion.hexToBigint(req.body.autoritiesPasswordSharedkeys[1].s), Number(bigintConversion.hexToBigint(req.body.autoritiesPasswordSharedkeys[1].Λ)),Number(bigintConversion.hexToBigint(req.body.autoritiesPasswordSharedkeys[1].t)),bigintConversion.hexToBigint(req.body.autoritiesPasswordSharedkeys[1].p))
    let autority3PasswordSharedKey:SharedKey= new SharedKey(bigintConversion.hexToBigint(req.body.autoritiesPasswordSharedkeys[2].s), Number(bigintConversion.hexToBigint(req.body.autoritiesPasswordSharedkeys[2].Λ)),Number(bigintConversion.hexToBigint(req.body.autoritiesPasswordSharedkeys[2].t)),bigintConversion.hexToBigint(req.body.autoritiesPasswordSharedkeys[2].p))
    let autoritiesPasswordSharedkeys:SharedKey[]=[autority1PasswordSharedKey,autority2PasswordSharedKey,autority3PasswordSharedKey]

    let autority1IVSharedKey:SharedKey= new SharedKey(bigintConversion.hexToBigint(req.body.autoritiesIVSharedkeys[0].s), Number(bigintConversion.hexToBigint(req.body.autoritiesIVSharedkeys[0].Λ)),Number(bigintConversion.hexToBigint(req.body.autoritiesIVSharedkeys[0].t)),bigintConversion.hexToBigint(req.body.autoritiesIVSharedkeys[0].p))
    let autority2IVSharedKey:SharedKey= new SharedKey(bigintConversion.hexToBigint(req.body.autoritiesIVSharedkeys[1].s), Number(bigintConversion.hexToBigint(req.body.autoritiesIVSharedkeys[1].Λ)),Number(bigintConversion.hexToBigint(req.body.autoritiesIVSharedkeys[1].t)),bigintConversion.hexToBigint(req.body.autoritiesIVSharedkeys[1].p))
    let autority3IVSharedKey:SharedKey= new SharedKey(bigintConversion.hexToBigint(req.body.autoritiesIVSharedkeys[2].s), Number(bigintConversion.hexToBigint(req.body.autoritiesIVSharedkeys[2].Λ)),Number(bigintConversion.hexToBigint(req.body.autoritiesIVSharedkeys[2].t)),bigintConversion.hexToBigint(req.body.autoritiesIVSharedkeys[2].p))
    let autoritiesIVSharedkeys:SharedKey[]=[autority1IVSharedKey,autority2IVSharedKey,autority3IVSharedKey]

    try
    {
        if (!getByCertificate(userCertificate)[0])
        {
            return res.status(400).json({
                msg: 'Aquest usuari no existeix'
            })
        }

        let userEncryptedDNI:string=getByCertificate(userCertificate)[1]

        if (!getUserDNI(userEncryptedDNI, autoritiesPasswordSharedkeys, autoritiesIVSharedkeys)[0])
        {
            return res.status(400).json({
                msg: 'Error al desencriptar el DNI sol·licitat'
            })
        }
           
        let userDNI:string=getUserDNI(userEncryptedDNI, autoritiesPasswordSharedkeys, autoritiesIVSharedkeys)[1]       

        
        let body = {            
            userDNI:userDNI
        }

        return res.status(200).json(body)

    }
    catch
    {
        return res.status(500).json({
            msg: 'Error al servidor'
        })

    }
    

}

//Rebem el certificat de l'usuari i retornem un repte RSA
export async function challengeUser(req:Request, res:Response) {

    let userRSAPubKey:RSAPublicKey=new RSAPublicKey(bigintConversion.hexToBigint(req.body.RSAPublicKey.e), bigintConversion.hexToBigint(req.body.RSAPublicKey.n))
    let userCertificate:Certificate= new Certificate(userRSAPubKey,bigintConversion.hexToBigint(req.body.ServerSignature))

    try
    {
        if (!verifySign)
        {
            return res.status(400).json({
                msg: 'Signatura incorrecta'
            })
        }

        
        let body = {
            challengeRSA:challengeRSA
        }

        return res.status(200).json(body)

    }
    catch
    {
        return res.status(500).json({
            msg: 'Error al servidor'
        })

    }    

}

//Rebem la resposta al repte i retornem un missatge conforme l'usuari ha estat verificat
export async function validateChallengeUser(req:Request, res:Response) {

    let userChallengeResponse:string=req.body.challengeRSA

    try
    {
        if (!validateChallengeRSA)
        {
            return res.status(400).json({
                msg: 'No ha superat el repte, probablement sigui un impostor.'
            })
        }

        
        let body = {
            msg: 'Usuari verificat'
        }

        return res.status(200).json(body)

    }
    catch
    {
        return res.status(500).json({
            msg: 'Error al servidor'
        })

    }    

}


