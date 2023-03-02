import express from 'express';
import cookieParser from 'cookie-parser';
import swaggerUi from 'swagger-ui-express';
import YAML from 'yaml';
import fs from 'fs';
import cors from 'cors';
import router from './routes/routes.js';

const app = express();

const data = fs.readFileSync('./swagger.yaml', { encoding: 'utf-8' });
const swaggerDocument = YAML.parse(data);
const options = { customCss: '.swagger-ui .topbar { display: none }' };
const corsOptions = { origin: ['https://localhost:4000/api-docs'] };

app.use(express.json());
app.use(cookieParser());
app.use(router);
app.use(cors(corsOptions));
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument, options));

export default app;
