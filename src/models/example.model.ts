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

export default new ExampleClass();