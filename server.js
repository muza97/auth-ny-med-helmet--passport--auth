if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
}

const express = require('express');
const bcrypt = require('bcrypt');
const passport = require('passport');
const flash = require('express-flash');
const session = require('express-session');
const methodOverride = require('method-override');
const helmet = require('helmet');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

const app = express();
const users = []; // This should be replaced with a database in production

const initializePassport = require('./passport-config');
initializePassport(
    passport,
    email => users.find(user => user.email === email),
    id => users.find(user => user.id === id)
);

// Define the findOrCreateUser function
async function findOrCreateUser(profile) {
    let user = users.find(user => user.googleId === profile.id);
    if (user) {
        return user;
    } else {
        user = {
            id: Date.now().toString(), // This should be a proper database ID in production
            name: profile.displayName,
            email: profile.emails[0].value,
            googleId: profile.id
        };
        users.push(user); // Replace with database logic in production
        return user;
    }
}

// Initialize Passport with the Google strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:4000/auth/google/callback"
},
  async (accessToken, refreshToken, profile, cb) => {
    const user = await findOrCreateUser(profile);
    cb(null, user);
  }
));

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] }));

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(flash());
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(methodOverride('_method'));
app.use(helmet.frameguard({ action: 'deny' }));

// Define the root route
app.get('/', (req, res) => {
    // Check if the user is authenticated to provide personalized content
    if (req.isAuthenticated()) {
        res.render('index.ejs', { name: req.user.name });
    } else {
        res.redirect('/login');
    }
});

app.get('/login', (req, res) => {
    if (req.isAuthenticated()) {
        // Användaren är redan inloggad, omdirigera till huvudsidan
        res.redirect('/');
    } else {
        // Användaren är inte inloggad, visa inloggningssidan
        res.render('login.ejs');
    }
});


app.get('/register', (req, res) => {
    res.render('register.ejs');
});

app.post('/register', async (req, res) => {
    try {
        // Antag att 'name', 'email', och 'password' skickas från registreringsformuläret
        const { name, email, password } = req.body;

        // Kontrollera om användaren redan finns (här använder vi en enkel array, men i en verklig applikation ska du använda en databas)
        if (users.find(user => user.email === email)) {
            // Om användaren finns, visa ett felmeddelande eller omdirigera
            res.redirect('/register'); // Eller visa ett felmeddelande
        } else {
            // Kryptera lösenordet
            const hashedPassword = await bcrypt.hash(password, 10);

            // Skapa en ny användare
            const newUser = { id: Date.now().toString(), name, email, password: hashedPassword };
            users.push(newUser); // I en verklig applikation, lägg till användaren i din databas

            // Omdirigera till login efter framgångsrik registrering
            res.redirect('/login');
        }
    } catch {
        res.redirect('/register');
    }
});

app.post('/login', passport.authenticate('local', {
    successRedirect: '/',       // Omdirigera till huvudsidan vid framgångsrik inloggning
    failureRedirect: '/login',  // Omdirigera tillbaka till inloggningssidan vid misslyckad inloggning
    failureFlash: true          // Tillåt flash-meddelanden vid inloggningsfel
}));



// Define logout route
app.delete('/logout', (req, res) => {
    req.logout(function(err) {
        if (err) { return next(err); }
        res.redirect('/login');
    });
});

app.get('/login', (req, res) => {
    res.render('login.ejs');
});

// Google OAuth routes
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    // Redirect to the root page after successful login
    res.redirect('/');
  });

  app.get('/auth/github',
  passport.authenticate('github'));

app.get('/auth/github/callback', 
  passport.authenticate('github', { failureRedirect: '/login' }),
  function(req, res) {
    // Framgångsrik autentisering, omdirigera hem.
    res.redirect('/');
  });

// Define other routes for login, register, etc.
// ...

// Start the server
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
