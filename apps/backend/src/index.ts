import { buildServer } from './server.js';
import { env } from './env.js';
const app = buildServer();
app.listen(env.PORT, () => console.log(`SAIccess API running on :${env.PORT}`));