import { Router } from 'express';
import swaggerUi from 'swagger-ui-express';
import openapi from '../docs/openapi.js';

const router = Router();
router.get('/openapi.json', (req, res) => res.type('application/json').json(openapi));
router.use('/', swaggerUi.serve);
router.get('/', swaggerUi.setup(openapi, {
  explorer: true,
  customSiteTitle: 'RelayVault API documentation',
}));

export default router;
