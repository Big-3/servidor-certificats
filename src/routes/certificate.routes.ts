// Example routes
import { Router } from "express";
import * as cFunctions from '../controllers/certificate.controller';

const certificate_routes = Router();

certificate_routes.route('/cert/issue')
    .post(cFunctions.issueCertificate);


export default certificate_routes;