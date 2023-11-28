require('dotenv').config();
import Koa from 'koa';
import Router from 'koa-router';
import bodyParser from 'koa-bodyparser';
import mongoose from 'mongoose';
import api from './api';
import jwtMiddleware from './lib/jwtMiddleware';
import cors from 'koa2-cors';

const { PORT, MONGO_URL } = process.env;

mongoose
  .connect(MONGO_URL, { useNewUrlParser: true, useUnifiedTopology: true, dbName: 'market' })
  .then(() => {
    console.log('Connected to MongoDB');
  })
  .catch(e => {
    console.error(e);
  });

const app = new Koa();
const router = new Router();

// CORS 활성화
app.use(cors());

// api 라우트 적용
router.use('/api', api.routes());

app.use(bodyParser());
app.use(jwtMiddleware);

// app 인스턴스에 라우터 적용
app.use(router.routes()).use(router.allowedMethods());

const port = PORT || 4000;
app.listen(port, () => {
  console.log('Listening to port %d', port);
});
