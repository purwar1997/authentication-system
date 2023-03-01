import express from 'express';
import cookieParser from 'cookie-parser';
import swaggerUi from 'swagger-ui-express';
import YAML from 'yaml';
import fs from 'fs';
import router from './routes/routes.js';

const app = express();
const data = fs.readFileSync('./swagger.yaml', { encoding: 'utf-8' });
const swaggerDocument = YAML.parse(data);

app.use(express.json());
app.use(cookieParser());
app.use(router);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

export default app;
