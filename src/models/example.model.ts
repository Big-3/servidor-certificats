import * as idUtils from '../utils/id.utils';
import {RSAPublicKey, RSAPrivateKey, generateRSAKeys} from '@big3/ciber-modules';
import crypto from "crypto"
import { genSharedKeys, LagrangeInterpolation, SharedKey } from '@big3/ciber-modules';
import * as bigintConversion from "bigint-conversion";

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

export class Certificate 
{
    private readonly PubKeyUser: RSAPublicKey
    private readonly ServerSignature: bigint
    
    constructor (PubKeyUser: RSAPublicKey, ServerSignature: bigint) {
        this.PubKeyUser = PubKeyUser
        this.ServerSignature = ServerSignature
    }
    
    public getPubKeyUser(): RSAPublicKey {
        return this.PubKeyUser
    }

    public getServerSignature(): bigint {
        return this.ServerSignature
    }
}

var autoritiesPasswordSharedkeysDataBase: Map<string,Promise<SharedKey[]>> = new Map()
var autoritiesIVSharedkeysDataBase: Map<string,Promise<SharedKey[]>> = new Map()
var CertificatesDatabase: Map<string,Certificate> = new Map()
var RSAchallengesDatabase: string[]
const ServerPrivateKey: RSAPrivateKey = await generateRSAKeys()

//****************************************funcions de POST /api/cert/issue****************************************
//La idea és que un usuari entregui al servidor el seu DNI i una clau RSA pública
//Aleshores el servidor en generarà el certificat amb aquesta RSA pública i la seva signatura
export function createCertificate (userPubKey: RSAPublicKey): [boolean, Certificate] 
{   
    try
    {
        return [true, new Certificate(userPubKey, ServerPrivateKey.sign(ServerPrivateKey.getRSAPublicKey().getExpE()))]
    }
    catch
    {
        return [false, <Certificate>{}]
    }
    
}

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

//****************************************funcions de GET /api/cert/user****************************************
//Una autoritat demana el DNI de l'usuari. Per fer-ho, entregarà el seu cerificat i les claus compartides
//Del certificat obtenim el DNI encriptat de l'usuari
export function getByCertificate(userCertificate:Certificate):[boolean, string] {
    for (let [key, value] of CertificatesDatabase.entries()) {
      if (value === userCertificate)
        return [true, key];
    }
    return [true, <string>{}]
}

//I amb aquest DNI encriptat obtingut podem dexifrar-ne el DNI amb criptografia llindar
export function getUserDNI (id: string, autoritiesPasswordSharedkeys:SharedKey[], autoritiesIvSharedkeys:SharedKey[]): [boolean, string] 
{   
    try
    {
        const alg =  'aes-256-cbc'
        let key = Buffer.from(LagrangeInterpolation(autoritiesPasswordSharedkeys).toString(), 'base64') 
        let iv = Buffer.from(LagrangeInterpolation(autoritiesIvSharedkeys).toString(), 'base64') 
        const decipher = crypto.createDecipheriv(alg, key, iv)
        let decrypted = decipher.update(id, 'hex', 'utf8');
        decrypted += decipher.final('utf8')
        return [true, decrypted]
    }
    catch
    {
        return [false, <string>{}]
    }
   
}

//****************************************funcions de GET /api/user/validate****************************************
//Primer se'n verifica la signatura
export function verifySign (userCertificate:Certificate): boolean
{   
    let receivedSign:bigint = userCertificate.getServerSignature()
    let success:boolean=false
    
    if (ServerPrivateKey.getRSAPublicKey().verify(receivedSign)==ServerPrivateKey.getRSAPublicKey().getExpE())
    {
        success=true
    }
    
    return success
}

//Ara ja podem fer el repte RSA encriptant un missatge qualsevol amb la clau pública de l'usuari
function randomMSG(length:number):string {
    let result:string           = '';
    let characters:string       = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let charactersLength:number = characters.length;
    for ( let i = 0; i < length; i++ ) {
      result += characters.charAt(Math.floor(Math.random() * 
 charactersLength));
   }
   return result;
}

//El missatge generat es desa per verificar-lo més tard
export function challengeRSA (userCertificate:Certificate): string 
{   
    let challengeMSG:string = randomMSG(2048)
    
    //Verifiquem que no existeixi a la base de dades, sinó tornem a generar el missatge fins que sigui únic
    while(RSAchallengesDatabase.indexOf(challengeMSG)!=-1)
    {
        challengeMSG = randomMSG(2048)
    }
    let userRSAPubKey:RSAPublicKey=userCertificate.getPubKeyUser()
    return bigintConversion.bigintToHex(userRSAPubKey.encrypt(bigintConversion.textToBigint(challengeMSG)))
}

//****************************************funcions de POST /api/cert/user****************************************
//Es verifica que el missatge dexifrat per l'usuari és el que hi havia encriptat. Si l'és, borrem el missatge de la memòria
export function validateChallengeRSA (decryptedMSG:string): boolean 
{   
    let decryptedChallengeMSG:string = bigintConversion.bigintToText(bigintConversion.hexToBigint(decryptedMSG))
    let success:boolean=false
    
    const index = RSAchallengesDatabase.indexOf(decryptedChallengeMSG);
    if (index > -1) 
    {
        RSAchallengesDatabase.splice(index, 1);
        success=true
    }
    
    return success
}
export default new ExampleClass();