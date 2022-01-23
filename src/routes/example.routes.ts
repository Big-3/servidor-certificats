// Example routes
import { Router } from "express";
import {generateCertificate, getUser, challengeUser, validateChallengeUser} from '../controllers/example.controller';

const example_routes = Router();

example_routes.route('/cert/issue')
    .get(generateCertificate);

example_routes.route('/cert/user')
    .post(getUser);

example_routes.route('/user/validate')
    .get(challengeUser);

example_routes.route('/user/validate')
    .post(validateChallengeUser);

export default example_routes;