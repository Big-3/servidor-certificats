import app from "./app";

async function main() {
    // What is the mode:
    const MODE = app.get('MODE');
    let ip = '';
    if(MODE=='dev'){
        ip = 'localhost';
    } else {
        ip = '';
    }


    // Make the express app listen to the PORT
    const PORT = app.get('PORT');
    await app.listen(PORT);
    
    // Message
    console.log('LISTENING @ ', PORT);
    console.log(`Refere to http://${ip}:${PORT}`);

}

main();