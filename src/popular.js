// Popular package names, used to spot typosquats ("reqeusts", "expres").
// Not exhaustive on purpose: these are the names attackers imitate most.

export const POPULAR = {
  npm: `react react-dom next vue nuxt svelte angular express koa fastify hono lodash underscore axios node-fetch got undici
request chalk commander yargs inquirer ora debug dotenv uuid nanoid moment dayjs date-fns luxon zod joi yup ajv
typescript ts-node tsx esbuild vite webpack rollup parcel babel-core @babel/core eslint prettier jest vitest mocha
chai sinon cypress playwright puppeteer jsdom cheerio ws socket.io redis ioredis mongoose mongodb pg mysql mysql2
sqlite3 better-sqlite3 prisma sequelize typeorm drizzle-orm knex graphql apollo-server body-parser cors helmet
morgan multer cookie-parser jsonwebtoken bcrypt bcryptjs passport sharp jimp canvas tailwindcss postcss autoprefixer
sass less styled-components emotion classnames clsx rxjs immer redux zustand mobx jquery bootstrap three d3 chart.js
electron nodemon pm2 concurrently cross-env rimraf glob fs-extra chokidar minimist semver colors color tslib core-js
regenerator-runtime webpack-cli vue-router react-router react-router-dom openai @anthropic-ai/sdk langchain ethers
web3 viem discord.js telegraf stripe aws-sdk firebase supabase @supabase/supabase-js puppeteer-core execa shelljs
cross-spawn yaml js-yaml xml2js marked markdown-it highlight.js prismjs handlebars ejs pug nunjucks mustache
lru-cache p-limit p-queue async bluebird eventemitter3 mitt ramda big.js bignumber.js decimal.js crypto-js
node-forge jose qs form-data formidable busboy http-proxy-middleware serve-static compression nodemailer winston
pino bunyan log4js`.split(/\s+/),
  pypi: `requests urllib3 numpy pandas scipy matplotlib seaborn scikit-learn tensorflow torch keras transformers
flask django fastapi uvicorn gunicorn starlette pydantic sqlalchemy psycopg2 psycopg2-binary pymongo redis celery
boto3 botocore awscli google-cloud-storage azure-storage-blob pillow opencv-python beautifulsoup4 lxml scrapy
selenium playwright httpx aiohttp websockets click typer rich colorama tqdm pyyaml toml python-dotenv jinja2
markupsafe werkzeug itsdangerous cryptography pycryptodome paramiko fabric pytest pytest-cov tox black flake8
pylint mypy isort ruff setuptools wheel pip virtualenv poetry pipenv six attrs dataclasses typing-extensions
python-dateutil pytz arrow pendulum simplejson ujson orjson msgpack protobuf grpcio openai anthropic langchain
tiktoken huggingface-hub datasets accelerate sentencepiece nltk spacy gensim xgboost lightgbm catboost statsmodels
sympy networkx plotly dash streamlit gradio jupyter notebook ipython ipykernel discord-py python-telegram-bot
tweepy pyautogui pynput keyboard psutil docker kubernetes ansible pexpect sh invoke apscheduler schedule
python-jose pyjwt passlib bcrypt argon2-cffi web3 solana ccxt yfinance openpyxl xlrd xlsxwriter reportlab pypdf2
pdfminer-six docx2txt python-docx markdown mistune pygments`.split(/\s+/),
};

export function editDistance(a, b) {
  if (Math.abs(a.length - b.length) > 2) return 3;
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i]);
  for (let j = 1; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1),
      );
      // adjacent swap ("reqeusts")
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) dp[i][j] = Math.min(dp[i][j], dp[i - 2][j - 2] + 1);
    }
  }
  return dp[a.length][b.length];
}

const norm = s => s.toLowerCase().replace(/^@[^/]+\//, '').replace(/[-_.]+/g, '');

export function lookalike(name, ecosystem) {
  const list = POPULAR[ecosystem] || [];
  if (list.includes(name)) return null;
  const n = norm(name);
  if (n.length < 4) return null;
  for (const p of list) {
    const q = norm(p);
    if (q.length < 4) continue;
    if (n === q) return p; // separator games: python_dateutil vs python-dateutil
    const d = editDistance(n, q);
    if (d === 1 || (d === 2 && q.length >= 8)) return p;
    // suffix/prefix tricks: "requests-toolbelt" is fine, "requestss" or "lodash-js" are not
    if (/^(js|py|node|python)$/.test(n.replace(q, '')) && n.length - q.length <= 6) return p;
  }
  return null;
}
