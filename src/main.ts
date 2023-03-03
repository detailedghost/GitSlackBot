import {
  _,
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
  z,
} from "./deps.ts";
import { Context } from "https://deno.land/x/oak@v11.1.0/mod.ts";

await dotenvLoad({
  examplePath: "./.env.example",
  allowEmptyValues: true,
  export: true,
});

const ConfigSchema = z.object({
  port: z
    .string()
    .default("3000")
    .transform((p) => +p),
  github: z.object({
    appId: z.string().min(1),
    appSecret: z.string().min(1),
    privateKey: z
      .string()
      .min(10)
      .transform((key: string) =>
        NodeRSA.default(key).exportKey("pkcs8-private-pem")
      )
      .optional(),
  }),
});
type ConfigSchema = z.infer<typeof ConfigSchema>;
const config = ConfigSchema.parse({
  port: Deno.env.get("PORT"),
  github: {
    appId: Deno.env.get("GH_APP_ID"),
    appSecret: Deno.env.get("GH_APP_SECRET"),
    privateKey: Deno.env.get("GH_PRIVATE_KEY"),
  },
});

const app = new Application<AppContext>({
  state: {
    logger: Logger.getLogger(),
  },
});

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

const octokit: Octokit = new Octokit({
  authStrategy: createAppAuth,
  auth: {
    appId: config.github.appId,
    privateKey: config.github.privateKey,
    installationId: nanoid(),
  },
  webhooks: {
    secret: config.github.appSecret,
  },
});

//console.log(await octokit.rest.apps.getAuthenticated());

const validateWebhookHeader = async (ctx: Context, next: () => unknown) => {
  const { request: req } = ctx;
  if (!req.hasBody) {
    ctx.throw(Status.BadRequest, "Bad Request");
  }
  const body = await req.body().value;
  const signature = req.headers.get("X-Hub-Signature-256")!;
  const verified = await verify(
    config.github.appSecret,
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

router.post("/webhook", validateWebhookHeader, async (ctx) => {
  const {
    request: req,
    response: res,
    state: { logger },
  } = ctx;
  const body = await req.body().value;

  logger.debug(JSON.stringify(body.repositories, undefined, 2));

  res.body = "PONG";
  res.status = 200;
});

type AppContext = {
  logger: Logger.Logger | Console;
  // deno-lint-ignore no-explicit-any
} & Record<string, any>;

app.use(async (ctx, next) => {
  if (_.isEmpty(ctx.state.logger)) {
    ctx.state.logger = Logger.getLogger();
  }
  await next();
});
app.use(router.routes());
app.use(router.allowedMethods());

app.addEventListener("listen", (ctx) => {
  Logger.getLogger().info(`Listening to ${ctx.port}`);
});
await app.listen({ port: config.port });
