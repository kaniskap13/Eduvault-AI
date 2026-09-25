import { app } from './app';
import { env } from './config/env';

app.listen(env.PORT, () => {
  console.log(`EduVault API listening on :${env.PORT} (${env.NODE_ENV})`);
});
