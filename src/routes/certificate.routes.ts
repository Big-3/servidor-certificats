// Example routes
import { Router } from "express";
import * as cFunctions from '../controllers/certificate.controller';

const certificate_routes = Router();

certificate_routes.route('/cert/issue')
    .post(cFunctions.issueCertificate);

certificate_routes.route('/public/key')
    .get(cFunctions.getPublicKey)

certificate_routes.route('/cert/user')
    .post(cFunctions.getDecrypted)

export default certificate_routes;