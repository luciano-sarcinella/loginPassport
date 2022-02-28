const express = require('express');
const app = express();
let expressSession = require('express-session');
let MongoStore = require('connect-mongo');
let passport = require('passport');
let passportStrategy = require('passport-local').Strategy;
let bCrypt = require('bcrypt')
let path = require('path');

const PORT = 3000;

let usuarios = [];

app.use(express.json());
app.use(express.urlencoded({extended:true}));

app.use(express.static(__dirname + "/public"));

app.set("views", path.join(__dirname, "views", "ejs"));
app.set('view engine', 'ejs');

//conecto a mongo
app.use(expressSession({
    store: MongoStore.create({mongoUrl: 'mongodb://localhost/sesiones2'}),
    secret: "secret",
    resave: true,
    saveUninitialized: true,
    cookie: {
        maxAge: 1000 * 60 * 10
    },
}));

passport.use('login', new passportStrategy((username,password, done)=>{
    let user = usuarios.find(usuario => usuario.username == username);

    if(!user)   return done(null, false);

    if(user.password != password)   return done(null, false);

    user.contador = 0;

    return done(null, user);
}));

passport.use('register', new passportStrategy({
    passReqToCallback: true
},(req, username,password, done)=>{
    let userfind = usuarios.find(usuario => usuario.username == username);
    
    if(userfind)   return done("already registered!");
    
    let user = {
        username: username,
        password: createHash(password),
        email:  req.body.email
    }
    
    usuarios.push(user);
    
    return done(null, user);

    function createHash(password){
        return bCrypt.hashSync(
            password,
            bCrypt.genSaltSync(10),
            null
        );

    }
}));

passport.serializeUser((user, done) =>{
    done(null, user.username);
});

passport.deserializeUser((username, done) =>{
    let user = usuarios.find(usuario => usuario.username == username);
    done(null, user);
});



app.use(passport.initialize());
app.use(passport.session());

let isAuth = (req, res, next) => {
    if (req.isAuthenticated()){
       return next(); 
    }
    res.redirect("/login")
};

let isNotAuth = (req, res, next) => {
    if (!req.isAuthenticated()){
        next();
    } else{
        res.redirect('/datos');
    }
};

app.get("/", (req, res, next)=>{
    res.redirect("login");
});

app.get("/registro", isNotAuth, (req, res, next)=>{
    res.render("registro");
});

app.post("/registro", passport.authenticate('register',{failureRedirect: 'registro-error', successRedirect: 'datos'}));


app.get("/login", (req, res, next)=>{
    res.render("login");
});

app.post("/login",passport.authenticate('login',{failureRedirect: 'registro', successRedirect: 'datos'}));


app.get("/datos", isAuth, (req, res, next)=>{
    if(!req.user.contador){
        req.user.contador = 1
    }else{
        req.user.contador ++;
    }
    res.render('datos', {
        contador: req.user.contador,
        usuario: req.user
    });
});

app.get("/logout", (req, res, next)=>{
    req.session.destroy(err => {
        if(err) res.send(JSON.stringify(err));
        res.redirect('login')
    });
});


app.listen(PORT, ()=>{
    console.log(`Server en puerto http://localhost:${PORT}`);
})