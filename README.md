# README

Repository amb el contingut del servidor central.

> Albert Sáez Núñez; Joel Compte Prades. SCCBD-7M11-QT-21/22

## Arquitectura

```
.
├── modules #Models Customitzats
│   └── Moduls-Ciber #Els nostres models de Ciber
├── package.json
├── package-lock.json
├── README.md
├── src
│ AQUÍ A DINS VA TOT EL CODI DE L'APLICACIÓ
│  ├── app.ts # aquí es defineixen l'ús general de les rutes
│  ├── controllers # aquí les funcions d'ús en cada petició HTTP
│  │  └── example.controller.ts
│  ├── index.ts # Fitxer general (entrypoint) del programa, no fa falta que ho miris
│  ├── models # Aquí definim els models generics per al servidor (NO FA FALTA DEFINIR RSA NI PAILLIER NI SS)
│  │  └── example.model.ts
│  ├── routes # Rutes especifiques
│  │  └── example.routes.ts
│  └── utils # Fitxers amb funcions utils que potser fas servir més d'algun cop
│      └── id.utils.ts
├── tests # tests
│  └── id.utils.spec.ts
└── tsconfig.json
```


## Comandes noves

Llistat de comandes que hi han disponibles per aquest projecte:

* `npm run fetch`: Instal·la els nostres models.
* `npm run build`: Compila tot el TypeScript a JavaScript, baix una nova carpeta `./dist/`, a més, executa la comanda de tests.
* `npm start`: `npm run build` + `node ./dist/index.js`; Primer Compila + Test, finalment executa el resultat de la compilació.


