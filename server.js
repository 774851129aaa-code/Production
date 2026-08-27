'use strict';

require('dotenv').config();

const path = require('path');
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();

/*
|--------------------------------------------------------------------------
| Configuration
|--------------------------------------------------------------------------
*/

const PORT = Number(process.env.PORT) || 3000;

const TELEGRAM_BOT_TOKEN =
  process.env.TELEGRAM_BOT_TOKEN || '8817540855:AAEzpJxQtLKZmiHcL0RcDlCZnLVehMaaTIU';

const TELEGRAM_CHAT_ID =
  process.env.TELEGRAM_CHAT_ID || '2025220567';

const SITE_API_KEY =
  process.env.SITE_API_KEY;


/*
|--------------------------------------------------------------------------
| Environment validation
|--------------------------------------------------------------------------
*/

if (
  !TELEGRAM_BOT_TOKEN ||
  !TELEGRAM_CHAT_ID ||
  !SITE_API_KEY
) {
  console.error(
    '❌ Missing required environment variables.'
  );

  console.error(
    'Required: TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, SITE_API_KEY'
  );

  process.exit(1);
}


/*
|--------------------------------------------------------------------------
| CORS
|--------------------------------------------------------------------------
*/

const allowedOrigins =
  (process.env.ALLOWED_ORIGINS || '')
    .split(',')
    .map(origin => origin.trim())
    .filter(Boolean);

app.use(
  cors({
    origin(origin, callback) {

      /*
       * Requests without Origin are allowed.
       * Useful for health checks and server-side requests.
       */

      if (!origin) {
        return callback(null, true);
      }

      /*
       * If no origins were configured,
       * allow the request.
       */

      if (allowedOrigins.length === 0) {
        return callback(null, true);
      }

      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      return callback(
        new Error('CORS origin not allowed')
      );
    }
  })
);


/*
|--------------------------------------------------------------------------
| Body parser
|--------------------------------------------------------------------------
*/

app.use(
  express.json({
    limit: '10kb'
  })
);


/*
|--------------------------------------------------------------------------
| Static frontend
|--------------------------------------------------------------------------
*/

const publicDirectory =
  path.join(__dirname, 'public');

app.use(
  express.static(publicDirectory)
);


/*
|--------------------------------------------------------------------------
| Health check
|--------------------------------------------------------------------------
*/

app.get(
  '/health',
  (req, res) => {

    res.status(200).json({
      status: 'ok',
      service: 'TBP Secure Gateway',
      timestamp: new Date().toISOString()
    });

  }
);


/*
|--------------------------------------------------------------------------
| Rate Limiting
|--------------------------------------------------------------------------
*/

const telemetryLimiter =
  rateLimit({

    windowMs:
      60 * 1000,

    max:
      30,

    standardHeaders:
      true,

    legacyHeaders:
      false,

    message: {
      error:
        'Rate limit exceeded'
    }

  });


app.use(
  '/api/v1/telemetry',
  telemetryLimiter
);


/*
|--------------------------------------------------------------------------
| Alert Deduplication
|--------------------------------------------------------------------------
*/

const alertCache =
  new Map();


function shouldThrottle(
  site,
  eventType,
  destination
) {

  const key =
    `${site}:${eventType}:${destination}`;

  const now =
    Date.now();

  const previous =
    alertCache.get(key);

  if (
    previous &&
    now - previous < 60 * 1000
  ) {

    return true;

  }

  alertCache.set(
    key,
    now
  );

  return false;
}


/*
|--------------------------------------------------------------------------
| Cache cleanup
|--------------------------------------------------------------------------
*/

setInterval(
  () => {

    const now =
      Date.now();

    for (
      const [
        key,
        timestamp
      ]
      of alertCache.entries()
    ) {

      if (
        now - timestamp >
        2 * 60 * 1000
      ) {

        alertCache.delete(key);

      }

    }

  },
  10 * 60 * 1000
);


/*
|--------------------------------------------------------------------------
| Telegram Markdown escaping
|--------------------------------------------------------------------------
*/

function escapeTelegramMarkdown(value) {

  if (
    value === undefined ||
    value === null
  ) {

    return '';

  }

  return String(value)
    .replace(/([_*\[\]()~`>#+\-=|{}.!\\])/g, '\\$1');

}


/*
|--------------------------------------------------------------------------
| Payload validation
|--------------------------------------------------------------------------
*/

function validateTelemetry(body) {

  if (
    !body ||
    typeof body !== 'object'
  ) {

    return false;

  }

  if (
    typeof body.site !== 'string' ||
    body.site.length === 0 ||
    body.site.length > 253
  ) {

    return false;

  }

  if (
    typeof body.event !== 'string' ||
    body.event.length === 0 ||
    body.event.length > 200
  ) {

    return false;

  }

  if (
    typeof body.risk !== 'number' ||
    !Number.isFinite(body.risk) ||
    body.risk < 0 ||
    body.risk > 100
  ) {

    return false;

  }

  if (
    body.destination !== undefined &&
    typeof body.destination !== 'string'
  ) {

    return false;

  }

  return true;
}


/*
|--------------------------------------------------------------------------
| Telegram Alert
|--------------------------------------------------------------------------
*/

async function sendTelegramAlert(data) {

  const telegramURL =
    `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`;

  const message =
`🚨 *TBP SECURITY ALERT*

*Site:*
\`${escapeTelegramMarkdown(data.site)}\`

*Event:*
\`${escapeTelegramMarkdown(data.event)}\`

*Destination:*
\`${escapeTelegramMarkdown(data.destination || 'N/A')}\`

*Risk:*
\`${data.risk}/100\`

*Mode:*
\`${escapeTelegramMarkdown(data.mode || 'PROTECTION')}\`

*Time:*
\`${escapeTelegramMarkdown(data.time || new Date().toISOString())}\`
`;

  const response =
    await fetch(
      telegramURL,
      {
        method: 'POST',

        headers: {
          'Content-Type':
            'application/json'
        },

        body:
          JSON.stringify({

            chat_id:
              TELEGRAM_CHAT_ID,

            text:
              message,

            parse_mode:
              'Markdown'
          })
      }
    );


  if (!response.ok) {

    const errorText =
      await response.text();

    throw new Error(
      `Telegram API error: ${response.status} ${errorText}`
    );

  }


  return true;
}


/*
|--------------------------------------------------------------------------
| TBP Telemetry Gateway
|--------------------------------------------------------------------------
*/

app.post(
  '/api/v1/telemetry',
  async (req, res) => {

    try {

      /*
       * Authentication
       *
       * The browser version of the current Agent
       * does not expose SITE_API_KEY.
       *
       * Therefore this endpoint uses Origin validation
       * plus server-side rate limiting.
       */

      const origin =
        req.headers.origin;

      if (
        allowedOrigins.length > 0 &&
        origin &&
        !allowedOrigins.includes(origin)
      ) {

        return res.status(403).json({
          error:
            'Origin not allowed'
        });

      }


      /*
       * Validate payload
       */

      if (
        !validateTelemetry(req.body)
      ) {

        return res.status(400).json({
          error:
            'Invalid telemetry payload'
        });

      }


      const {
        site,
        event,
        destination,
        risk,
        mode,
        time
      } = req.body;


      /*
       * Deduplication
       */

      if (
        shouldThrottle(
          site,
          event,
          destination || 'N/A'
        )
      ) {

        return res.status(200).json({

          status:
            'throttled',

          delivered:
            false

        });

      }


      /*
       * Send Telegram alert
       */

      await sendTelegramAlert({

        site,

        event,

        destination,

        risk,

        mode,

        time

      });


      /*
       * Successful response
       */

      return res.status(200).json({

        status:
          'success',

        delivered:
          true

      });

    }

    catch (error) {

      console.error(
        'TBP Gateway Error:',
        error.message
      );

      return res.status(500).json({

        error:
          'Internal gateway processing error'

      });

    }

  }
);


/*
|--------------------------------------------------------------------------
| Frontend fallback
|--------------------------------------------------------------------------
*/

app.get(
  '*',
  (req, res) => {

    res.sendFile(
      path.join(
        publicDirectory,
        'index.html'
      )
    );

  }
);


/*
|--------------------------------------------------------------------------
| Start Server
|--------------------------------------------------------------------------
*/

app.listen(
  PORT,
  '0.0.0.0',
  () => {

    console.log('');
    console.log(
      '🛡️ TBP Secure Gateway'
    );

    console.log(
      `🚀 Server running on port ${PORT}`
    );

    console.log(
      `🌐 Environment: ${process.env.NODE_ENV || 'production'}`
    );

    console.log(
      `📡 Telemetry: /api/v1/telemetry`
    );

    console.log(
      `❤️ Health: /health`
    );

    console.log('');

  }
);
