import {
  Application,
  createAppAuth,
  dotenvLoad,
  Logger,
  nanoid,
  NodeRSA,
  Octokit,
  Router,
  Status,
  verify,
} from "./deps.ts";
import type { RouterContext } from "./deps.ts";
import { Context } from "https://deno.land/x/oak@v11.1.0/mod.ts";
const ENVIRONMENT = Deno.env.get("ENVIRONMENT");

await dotenvLoad({
  envPath: `./.env.${ENVIRONMENT}`,
  examplePath: "./.env.example",
  allowEmptyValues: true,
  export: true
});

const PORT = Number(Deno.env.get("PORT")) || 3000;
const GH_APP_ID = Number(Deno.env.get("GH_APP_ID"));
const GH_APP_SECRET = Deno.env.get("GH_APP_SECRET");
const envPrivateKey = Deno.env.get("GH_PRIVATE_KEY");
const GH_PRIVATE_KEY = NodeRSA.default(envPrivateKey).exportKey("pkcs8-private-pem");

Logger.setup({
  handlers: {
    console: new Logger.handlers.ConsoleHandler("DEBUG", {
      formatter: "[{levelName}] {msg}",
    }),
  },
  loggers: {
    default: {
      level: "DEBUG",
      handlers: ["console"],
    },
  },
});

const app = new Application();

const octokit: Octokit = new Octokit({
  authStrategy: createAppAuth,
  auth: {
    appId: GH_APP_ID,
    privateKey: GH_PRIVATE_KEY,
    installationId: nanoid(),
  },
  webhooks: {
    secret: GH_APP_SECRET,
  },
});

console.log(await octokit.rest.apps.getAuthenticated());

const validateWebhookHeader =
  () => async (ctx: Context, next: () => unknown) => {
    const { request: req } = ctx;
    if (!req.hasBody) {
      ctx.throw(Status.BadRequest, "Bad Request");
    }
    const body = await req.body().value;
    const signature = req.headers.get("X-Hub-Signature-256")!;
    const verified = await verify(
      GH_APP_SECRET,
      JSON.stringify(body),
      signature
    );
    if (!verified) {
      ctx.throw(Status.Forbidden, "Invalid Credentials");
    }
    await next();
  };

const router = new Router();

router.get("/", ({ response }) => {
  response.body = "Hello World";
  response.status = 200;
});

router.post("/webhook", validateWebhookHeader(), async (ctx) => {
  const {
    request: req,
    response: res,
    state: { logger },
  } = ctx;
  const body = await req.body().value;
  logger.debug(body.hook);

  res.body = "PONG";
  res.status = 200;
});

app.use(async (ctx, next) => {
  if (!ctx.state.logger) {
    ctx.state.logger = Logger.getLogger();
  }
  await next();
});
app.use(router.routes());
app.use(router.allowedMethods());

Logger.getLogger().info(`Listening to ${PORT}`);

await app.listen({
  port: PORT,
});
