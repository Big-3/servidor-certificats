// Example routes
import { Router } from "express";
import { addExample, getExample } from '../controllers/example.controller';

const example_routes = Router();

example_routes.route('/cert/example/:id')
    .get(getExample);

example_routes.route('/cert/add/example')
    .post(addExample);

export default example_routes;