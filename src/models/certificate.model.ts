import { generateRSAKeys, RSAPrivateKey, RSAPublicKey } from "@big3/ciber-modules";
import { bigintToHex, hexToBigint, bigintToText } from "bigint-conversion";
import {Logger} from "tslog";
import { genDniId } from "../utils/id.utils";

export class Certificate{
    private _pubKey : RSAPublicKey;
    private _serverSignature : bigint;
    private _logger: Logger;

    constructor (pubKey: RSAPublicKey, serverSignature: bigint) {
        this._pubKey = pubKey;
        this._serverSignature = serverSignature;
        this._logger = new Logger();
    }

    getSafeJsonCertificate(): any {
        this._logger.info(`Getting JSON safe Certificate`);
        var safeCertificate = {
            publicKey: this.getJsonSafePubKey(),
            serverSignature: this.getJsonSafeServerSignature()
        };
        return safeCertificate;
    }

    getJsonSafePubKey(): any {
        this._logger.info(`GETTING SAFE JSON KEY`);
        var safeKey = {
            e: bigintToHex(this._pubKey.getExpE()),
            n: bigintToHex(this._pubKey.getModN())
        }
        return safeKey;
    }

    getPubKey(): RSAPublicKey{
        return this._pubKey;
    }

    getJsonSafeServerSignature(): any {
        this._logger.info(`GETTING SAFE JSON SIGNATURE`);
        var safeSignature = bigintToHex(this._serverSignature);
        return safeSignature;
    }

    getServerSignature(): bigint{
        return this._serverSignature;
    }
}

export class CertificateManager{
    private _certificates: Map<string, Certificate>;
    private _privateKey: RSAPrivateKey;
    private _logger: Logger = new Logger();

    constructor(privateKey: RSAPrivateKey) {
        this._certificates = new Map<string, Certificate>();
        this._privateKey = privateKey;
    }

    static async init(): Promise<CertificateManager>{
        const logger = new Logger();
        logger.info(`New init process for new server key`);
        const privateKey = await generateRSAKeys(128);

        return new CertificateManager(privateKey);
    }

    getPrivateKey(): RSAPrivateKey{
        return this._privateKey;
    }

    addCertificate(userCertificate: Certificate, dni: string): [Boolean, Buffer | undefined, Buffer | undefined] {
        const [id, key, iv] = genDniId(dni);
        this._logger.info(`New petition to add entry`);
        if(this._certificates.has(id)){
            this._logger.warn(`Entry is already defined, Skipping petition.`);
            return [false, undefined, undefined];
        } else {
            this._certificates.set(id, userCertificate);
            return [true, key, iv];
        }
    }

    getJsonSafePublicKey(): any{
        var safePublicKey = {
            e: bigintToHex(this._privateKey.getRSAPublicKey().getExpE()),
            n: bigintToHex(this._privateKey.getRSAPublicKey().getModN())
        }
        return safePublicKey;
    }

    getCertificate(id: string): Certificate | undefined {
        this._logger.info(`New petition to get ${id}`);
        return this._certificates.get(id);
    }

    getIdByCertificate(userCertificate: Certificate): [Boolean, string | undefined] {
        this._logger.info(`New petition to get an idKEY`);
        for (let [key, value] of this._certificates.entries()) {
            if (value === userCertificate){
                this._logger.info(`HIT. Found entry.`);
                return [true, key];
            }
        }
        this._logger.warn(`No entry was found.`);
        return [true, undefined];
    }
}