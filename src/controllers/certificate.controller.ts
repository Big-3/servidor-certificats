import { Request, Response } from "express";
import { Certificate, CertificateManager } from "../models/certificate.model";
import * as certUtils from '../utils/certificate.utils';
import { Logger } from "tslog";
const logger = new Logger();

var certificateManager: any;
CertificateManager.init()
    .then(
        (data) => {
            logger.info(`System Key has been generated`);
            certificateManager = data;
        }
    );

export async function issueCertificate(req: Request, res: Response) {
    try{
        const {pubRawKey, dni, blindCipher} = req.body;
        if(typeof pubRawKey === 'undefined' || typeof dni === 'undefined' || typeof blindCipher === 'undefined'){
            return res.status(400).json({msg: 'bad request.'});
        } else {
            const pubKey = await certUtils.rsaPubKeyFromHex(pubRawKey);
            const [issued, userCertificate] = certUtils.createCertificate(pubKey!, certificateManager.getPrivateKey(), blindCipher);

            if(issued){
               const [added, key, iv] =  await certificateManager.addCertificate(userCertificate, dni);
               return res.status(200).json(userCertificate.getSafeJsonCertificate());
            } else {
                return res.status(400).json({msg: `Could not issue certificate.`});
            }
        }
    } catch (err) {
        console.log(err);
        return res.status(500).json({msg: "Server Error."});
    }
}

export async function getPublicKey(req: Request, res: Response){
    try{
        const safePublicKey = certificateManager.getJsonSafePubKey();
        return res.status(200).json({safePublicKey});
    } catch (err) {
        console.log(err);
        return res.status(500).json({msg: "Server Error."});
    }
}