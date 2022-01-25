import * as idUtils from '../utils/id.utils';
import {RSAPublicKey, RSAPrivateKey, generateRSAKeys} from '@big3/ciber-modules';
import crypto from "crypto"
import { genSharedKeys, LagrangeInterpolation, SharedKey } from '@big3/ciber-modules';
import * as bigintConversion from "bigint-conversion";
import { Certificate } from './certificate.model';

class ExampleClass {
    private _exampleMap;

    constructor() {
        this._exampleMap = new Map();
    }

    addSomething(something: any, id?:String): Boolean {
        let idSomething: String = id || idUtils.genRandomId(); // Si una id, es passa com a parametre, fes-la servir, per el contrari (||) fes servir la proposada.

        // check ID already in MAP
        while (this._exampleMap.has(id)){
            idSomething = idUtils.genRandomId();
        }

        try {
            this._exampleMap.set(idSomething, something);
            console.log(`Added Something @ ${idSomething}`);
            return true;
        } catch {
            console.log('Something wrong happened');
            return false;
        }
    }

    getSomething(id: String): any{
        return this._exampleMap.get(id);
    }
}

/*
var autoritiesPasswordSharedkeysDataBase: Map<string,Promise<SharedKey[]>> = new Map()
var autoritiesIVSharedkeysDataBase: Map<string,Promise<SharedKey[]>> = new Map()
var CertificatesDatabase: Map<string,Certificate> = new Map()
var RSAchallengesDatabase: string[]
const ServerPrivateKey: RSAPrivateKey = await generateRSAKeys()

//Després, desarà el Certificat a la seva base de dades essent-ne el DNI encriptat el seu identificador.
//Finalment retornarà les claus compartides i envarà cadascuna a les diferents autoritats amb el seu respectiu certificat
export function addCertificateANDSharedKeysToDB (userCertificate:Certificate,DNI:string): boolean
{
    try
    {
        const alg =  'aes-256-cbc'
        let password = crypto.randomBytes(32).toString('hex')
        let key = Buffer.from(password, 'hex')
        let iv = crypto.randomBytes(16)
        let cipher = crypto.createCipheriv(alg, key, iv)
        let msgUtf8 = DNI    
        let encrypted = cipher.update(msgUtf8, 'utf8', 'hex');
        encrypted += cipher.final('hex');
    
        //El DNI encriptat serà el nostre id
        let id:string = encrypted
    
        // check ID already in MAP
        while (CertificatesDatabase.has(id))
        {
            password = crypto.randomBytes(32).toString('base64')
            key = Buffer.from(password, 'base64')
            iv = crypto.randomBytes(16)
            cipher = crypto.createCipheriv(alg, key, iv)
            msgUtf8 = DNI        
            encrypted = cipher.update(msgUtf8, 'utf8', 'hex');
            encrypted += cipher.final('hex');
    
            id = encrypted
        }
        CertificatesDatabase.set(id,userCertificate)
    
        let passwordSharedkeys: Promise<SharedKey[]>=genSharedKeys(bigintConversion.bufToBigint(key), 3, 3,2048)
        let IVSharedkeys: Promise<SharedKey[]>=genSharedKeys(bigintConversion.bufToBigint(iv), 3, 3,2048)

        autoritiesPasswordSharedkeysDataBase.set(id,passwordSharedkeys)
        autoritiesIVSharedkeysDataBase.set(id,IVSharedkeys)
    
        return true  
    }
    catch
    {
        return false 
    }
    
}
*/
export default new ExampleClass();