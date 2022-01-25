import crypto from 'crypto';

export function genRandomId(): String{
    return "string";
}

export function genDniId(dni: string, optAlgorithm?: string): [string, Buffer, Buffer] {
    let idEncrypted: string = "";
    const algorithm = optAlgorithm || "aes-256-cbc";

    // KEY PARAMETERS
    const password = crypto.randomBytes(32).toString('hex');
    const key = Buffer.from(password, 'hex');
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    const msgUtf8 = dni;
    idEncrypted = cipher.update(msgUtf8, 'utf8', 'hex');
    idEncrypted += cipher.final('hex');

    return [idEncrypted, key, iv];
}

export function getRandomInt (min: number, max: number): string {
    min = Math.ceil(min)
    max = Math.floor(max)
    return (Math.floor(Math.random() * (max - min + 1)) + min).toString()
}