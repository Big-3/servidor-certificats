import { Request, Response } from "express";
import { Certificate, CertificateManager } from "../models/certificate.model";
import * as axios from 'axios';
import * as certUtils from '../utils/certificate.utils';
import * as shamir from 'shamirs-secret-sharing-ts';
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
                const secret = Buffer.from(dni);
                const shares = shamir.split(secret, {shares: 3, threshold: 2});
                let safeShares: string[] = [];
                shares.forEach(
                    (item) =>{
                        logger.info(`share ${item}`);
                        safeShares.push(item.toString('hex'));
                    }
                );
               const [added, key, iv] =  await certificateManager.addCertificate(userCertificate, dni);
               const safeUserCertificate = userCertificate.getSafeJsonCertificate();
               logger.info(`Enviant share a autoritari`);
               axios.default.post('http://localhost:9090/api/add',{safeUserCertificate, share: safeShares[0]}).then(
                   (data) =>{
                        logger.info(`Enviant share a autoritari`);
                        axios.default.post('http://localhost:8888/api/add',{safeUserCertificate, share: safeShares[1]}).then(
                           (data) => {
                            logger.info(`Enviant share a autoritari`);
                            axios.default.post('http://localhost:9999/api/add',{safeUserCertificate, share: safeShares[2]}).then(
                                (data) => {
                                    logger.info(`Tot bé`);
                                    return res.status(200).json(safeUserCertificate); 
                                }
                            );
                           }
                       );
                   }
               );
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
        const safePublicKey = certificateManager.getJsonSafePublicKey();
        return res.status(200).json({safePublicKey});
    } catch (err) {
        console.log(err);
        return res.status(500).json({msg: "Server Error."});
    }
}

export async function getDecrypted(req:Request, res: Response) {
    try{
        const {safeShares} = req.body;
        const dni: string = certUtils.decryptDNI(safeShares);
        return res.status(200).json({dni: dni});
    } catch (err) {
        console.log(err);
        return res.status(500).json({msg: "Server Error."});
    } 
}