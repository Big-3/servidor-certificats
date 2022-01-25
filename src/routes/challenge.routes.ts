// Example routes
import { Router } from "express";
import * as cFunctions from '../controllers/challenge.controller';

const challenge_routes = Router();

challenge_routes.route('/validation/instantiate')
    .post(cFunctions.instantiateChallenge);

challenge_routes.route('/validation/validate')
    .post(cFunctions.validateChallenge);

export default challenge_routes;