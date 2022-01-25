import { Request, Response } from "express";
import { RSAChallenge, RSAChallengeManager, rsaChallengeManager } from "../models/rsaChallenge.model";
import { certificateFromSafeJson } from "../utils/certificate.utils";
import { Logger } from "tslog";
import { Certificate } from "../models/certificate.model";
const logger = new Logger();


export async function instantiateChallenge(req:Request, res: Response) {
    const safeCertificate = req.body;
    try{
        if(typeof safeCertificate === 'undefined'){
            logger.warn('Bad Request');
            return res.status(400).json({msg: "bad request."});
        } else {
            const certificate: Certificate | undefined = certificateFromSafeJson(safeCertificate);
            if(typeof certificate !== 'undefined'){
                const rsaChallenge: RSAChallenge = RSAChallenge.init(certificate);
                const [success, id] = rsaChallengeManager.addRsaChallenge(rsaChallenge);

                if(success){
                    logger.info(`Challenge creation successful`);
                    return res.status(200).json({id: id, challenge: rsaChallenge.getSafeChallengeText()});
                } else {
                    return res.status(400).json({msg: "Could not create Challenge"});
                }
            } else {
                return res.status(400).json({msg: "bad operation."});
            }
        }

    }catch(err){
        logger.fatal(err);
        return res.status(500).json({msg: "server error."});
    }
}

export async function validateChallenge(req:Request, res:Response) {
    const {id, decryptedMSG} = req.body;
    try{
        if(typeof decryptedMSG !== 'undefined' || typeof id !== 'undefined'){
            const validated: Boolean = rsaChallengeManager.validateChallenge(id, decryptedMSG);
            if(validated){
                return res.status(200).json({msg: "Validated."});
            } else {
                return res.status(403).json({msg: "Unauthorised."});
            }
        } else {
            return res.status(400).json({msg: "Bad Request."});
        }
    } catch (err) {
        return res.status(500).json({msg: "Internal Server Error."});
    }
}