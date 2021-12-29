const express = require('express');
const expressSession = require('express-session');
const cookieParser = require('cookie-parser');
const handlebars = require('express-handlebars');
const cluster = require('cluster');
const mongoose = require('mongoose');
const TwitterStrategy = require('passport-twitter').Strategy;
const compression = require('compression');
const log4js = require('log4js');

/////////////////*LOG4JS*////////////////////////
log4js.configure({
  appenders: {
      miLoggerConsole: {type: "console"},
      miLoggerFileWarning: {type: 'file', filename: 'warn.log'},
      miLoggerFileError: {type: 'file', filename: 'error.log'}
  },
  categories: {
      default: {appenders: ["miLoggerConsole"], level:"trace"},
      info: {appenders: ["miLoggerConsole"], level: "info"},
      warn: {appenders:["miLoggerFileWarning"], level: "warn"},
      error: {appenders: ["miLoggerFileError"], level: "error"}
  }
});

const loggerInfo = log4js.getLogger('info');
const loggerWarn = log4js.getLogger('warn');
const loggerError = log4js.getLogger('error');

/////////////////*PASSPORT*//////////////////////// 

const passport = require('passport');
const bcrypt = require('bcrypt');

/////////////////*RUTAS*//////////////////////// 

const User = require('./models');

////////////////*HASH*///////////////////////////

const createHash = (password) => bcrypt.hashSync(password, bcrypt.genSaltSync(10));
const isValidPassword = (user, password) => bcrypt.compareSync(password, user.password);

// TEST APP
const PORT = process.argv[2] || 8080;
const TWITTER_CLIENT_ID = process.argv[3] || 'fX8rSWtkYfLQyRcLNzk08sEzv';
const TWITTER_CLIENT_SECRET = process.argv[4] || 'qZP9sNi4lUM8LOOR0mpfbVXutJD6qHz7ckq7szujDnjI7l9T7n';
const modoCluster = process.argv[5] == 'CLUSTER'

///////////////*Login con Twitter*////////////////////

/* MASTER */

if(modoCluster && cluster.isMaster) {
  // if Master, crea workers

  console.log(`Master ${process.pid} is running`);

  // fork workers
  for (let i=0; i<numCPUs; i++){
      cluster.fork()
  };

  cluster.on('exit', (worker, code, signal) => {
      console.log(`Worker ${worker.process.pid} died`);
  });
} else {
  // if !Master, alta al servidor + resto funcionalidades

  passport.use(
    new TwitterStrategy(
      {
        consumerKey: TWITTER_CLIENT_ID,
        consumerSecret: TWITTER_CLIENT_SECRET,
        callbackURL: '/auth/twitter/callback',
      },
      (_token, _tokenSecret, profile, done) => {
        console.log(profile);
  
        return done(null,profile,);
      }));


passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

//////////////////////////////////////

const app = express();

//////////////////////////////////////////////////

app.set("views", "./views");
app.set("view engine", "ejs");

/////////////////////////////////////

app.use(express.json());
app.use(express.urlencoded({extended:true}));

app.use(
  expressSession({
    secret: 'keyboard cat',
    cookie: {
      httpOnly: false,
      secure: false,
      maxAge: 60 * 10 * 1000,
    },
    rolling: true,
    resave: true,
    saveUninitialized: false,
  }),
);

app.use(passport.initialize());
app.use(passport.session());

/////////////////*COMPRESSION*//////////////////////// 

app.use(compression());

//////////////////////////////////////

const loginStrategyName = 'login';
const signUpStrategyName = 'signup';


const checkAuthentication = (request, response, next) => {
  if (request.isAuthenticated()) {
    return next();
  }

  return response
    .redirect(302, '/login');
};

/* Loguear usuario  */

app.get('/', (_request, response) => response.render(`pages/index`));

app.post(
  '/login',
  passport.authenticate(loginStrategyName, { failureRedirect: '/faillogin' }),
  (request, response) => {

  let nombre = request.user.username
  response.render(`pages/main`, {user : nombre})
  }
);

app.get('/faillogin', (_request, response) => response.render(`pages/faillogin`));

app.get('/main', (request, response) => {
  let usuario = request.user;
  response.render(`pages/main`, {user: usuario})
}
  );

app.get('/auth/twitter',passport.authenticate('twitter'),);

app.get(
  '/auth/twitter/callback',
  passport.authenticate(
    'twitter',
    {
      successRedirect: '/main',
      failureRedirect: '/faillogin',
    },
  ),
);


/* Registrar usuario */

app.get('/signup', 
  (_request, response) => response.render(`pages/signup`));

app.post(
  '/signup',
  passport.authenticate(signUpStrategyName, { failureRedirect: '/failsignup' }),
  (_request, response) => response.render(`pages/index`),
);

app.get('/failsignup', (_request, response) => response.render(`pages/failsignup`));

/* Deslogueo */

app.get('/logout', (request, response) => {
  const {user} = request.query;  
  
  request.logout();
  
  return response.status(200).render(`pages/logout`, {user: user})
});

/* -------------- GLOBAL PROCESS & CHILD PROCESS -------------- */

// PROCESS
app.get('/info', (request, response) => {

  let info = {
    rgEntrada: JSON.stringify(process.argv, null, '\t'), 
    os: process.platform, 
    nodeVs: process.version, 
    memoryUsage: JSON.stringify(process.memoryUsage()), 
    excPath: process.execPath, 
    processID: process.pid, 
    folder: process.cwd(),
    numCPUs
};

// test
//console.log(info);

  response.render("info", info);


});


/** ---------------- * NGINX *--------------------------- **/

app.get(
  '/datos',
  (_request, response) => {
    console.log(`PORT: ${PORT} --> FYH: ${Date.now()}`);

    return response
      .status(200)
      .send(`Servidor Express <span style="color: blueviolet;">(Nginx)</span> en ${PORT} - <b>PID ${process.pid}</b> - ${new Date().toLocaleString()}`);
  },
);
/*
// CHILD PROCESS
const {fork} = require('child_process');

// /randoms?cant=20000
app.get('/randoms', (request, response) => {
  try{
   const randomNumber = fork('./child.js');
   
   randomNumber.send(request.query);
   randomNumber.on('message', numerosRandom => {
       response.end(`Numeros random ${JSON.stringify(numerosRandom)}`);
   });
 } catch (err) {
   loggerError.error(err);
 }
});
*/
/// //////////////////////////////////////////////////

function conectarDB(url, callback) {
  mongoose.connect(
    url,
    {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    },
    (error) => {
      if (!error && callback != null) {
        return callback(error);
      }

      throw error;
    },
  );
}

module.exports = {
  conectarDB,
};

conectarDB("mongodb://localhost:27017/passport", (error) => {
  if (error) {
    loggerWarn.error('error en conexión de base de datos', error);

    return;
  }

  loggerInfo.info('Base de datos conectada')

  app.listen(PORT, (error) => {
    if (error) {
      loggerError.error(err)

      return;
    }

    loggerInfo.info(`Server running on port ${PORT}`);
  });
});

process.on('exit', code => {
    console.log(code)
  })

  loggerInfo.info(`Worker ${process.pid} started`);
};