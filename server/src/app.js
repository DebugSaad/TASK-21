require("dotenv").config();
const fastify = require("fastify")({ logger: true });
const oauthPlugin = require('@fastify/oauth2');

fastify.register(require("@fastify/cors"), { origin: true });

fastify.register(require("@fastify/jwt"), {
  secret: process.env.JWT_SECRET || 'supersecret',
});

fastify.decorate("authenticate", async function (request, reply) {
  try {
    await request.jwtVerify();
  } catch (err) {
    reply.send(err);
  }
});

fastify.register(oauthPlugin, {
  name: 'googleOAuth2',
  scope: ['profile', 'email'],
  credentials: {
    client: {
      id: process.env.GOOGLE_CLIENT_ID , 
      secret: process.env.GOOGLE_CLIENT_SECRET,
    },
    auth: oauthPlugin.GOOGLE_CONFIGURATION
  },
  startRedirectPath: '/api/auth/google',
  callbackUri: 'http://localhost:4000/api/auth/google/callback' 
});

fastify.register(require("./features/auth/auth.routes"), {
  prefix: "/api/auth",
});

const start = async () => {
  try {
    const port = process.env.PORT || 3000;
    await fastify.ready(); 

    await fastify.listen({ port: port });
    console.log(`Server running on http://localhost:${port}`);
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();