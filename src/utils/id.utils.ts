export function genRandomId(): String{
    return "string";
}

export function getRandomInt (min: number, max: number): string {
    min = Math.ceil(min)
    max = Math.floor(max)
    return (Math.floor(Math.random() * (max - min + 1)) + min).toString()
}