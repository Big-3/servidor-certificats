import { RSAPublicKey } from "@big3/ciber-modules";
import { hexToBigint, textToBuf, bufToHex, bigintToHex } from "bigint-conversion";
import { Logger } from "tslog";
import * as bcu from 'bigint-crypto-utils';
import { randomMSG } from "../utils/challenge.utils";
import { genRandomId } from "../utils/id.utils";
import { Certificate } from "./certificate.model";

export class RSAChallenge{
    private _clearText: string;
    private _challengeText: bigint;
    private _logger: Logger = new Logger();

    constructor (clearText: string, challengeText: bigint) {
        this._challengeText = challengeText;
        this._clearText = clearText;
    }

    static init(userCertificate: Certificate): RSAChallenge{
        const logger = new Logger();
        logger.info('New RSA challenge');
        const clearText = bigintToHex((bcu.randBetween(userCertificate.getPubKey().getModN(), 128n)));
        const userPubKey: RSAPublicKey = userCertificate.getPubKey();
        const challengeText = userPubKey.encrypt(hexToBigint(clearText));

        logger.info(`New RSA challenge created {${clearText}, ${challengeText}}`);
        return new RSAChallenge(clearText, challengeText);
    }

    getClearText(): string{
        return this._clearText;
    }

    getChallengeText(): bigint{
        return this._challengeText;
    }

    getSafeChallengeText(): string {
        return bigintToHex(this._challengeText);
    }
}

export class RSAChallengeManager{
    private _challenges: Map<String, RSAChallenge>;
    private _logger: Logger;

    constructor() {
        this._challenges = new Map<String, RSAChallenge>();
        this._logger = new Logger();
    }

    addRsaChallenge(challenge: RSAChallenge): [Boolean, String]{
        this._logger.info(`New petition to add RSA challenge`);
        let id = randomMSG();

        while(this._challenges.has(id)){
            id = randomMSG();
        }

        this._challenges.set(id, challenge);
        this._logger.info(`Challenge pushed with id ${id}`);
        return [true, id];

    }

    validateChallenge(id: String, decryptedMSG: string): Boolean{
        let decryptedChallengeMSG:string = decryptedMSG;
        let success:boolean=false;
        
        this._logger.info(`New petition to validate ${id} with ${decryptedMSG}`);

        const challenge = this._challenges.get(id);
        if(challenge!.getClearText() == decryptedChallengeMSG){
            this._logger.info(`Session ${id} validated.`);
            this._challenges.delete(id);
            success = true;
        } else {
            this._logger.warn(`Session ${id} not found or not validated.`);
        }
        
        return success;
    }
}

export let rsaChallengeManager: RSAChallengeManager = new RSAChallengeManager();