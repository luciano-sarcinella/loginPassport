const express = require('express');
let jwt = require('jsonwebtoken')
const app = express();
const PORT = 3000;
let path = require('path');
const private_key = 'clavesecreta';;

let usuarios = [];

app.use(express.json());
app.use(express.urlencoded({extended:true}));

app.use(express.static(__dirname + "/public"));

app.set("views", path.join(__dirname, "views", "ejs"));
app.set('view engine', 'ejs');

let isAuth = async (req, res, next) => {
    const authHeader = req.headers.athorization;
    if (!authHeader) return res.send("No estas autenticado!");

    const token = authHeader.split(" ")[1];
    let dataToken = await jwt.verify(token, private_key);
    req.user = dataToken.data;
    next();
};


app.get("/", (req, res, next)=>{
    res.redirect("login");
});

app.get("/registro", (req, res, next)=>{
    res.render("registro");
});


app.get("/login", (req, res, next)=>{
    res.render("login");
});



app.get("/datos", isAuth, (req, res, next)=>{
    res.json(req.user);
});

app.get("/logout", (req, res, next)=>{
    req.session.destroy(err => {
        if(err) res.send(JSON.stringify(err));
        res.redirect('login')
    });
});


app.post("/registro", async (req, res, next)=>{
    let {username, password, direccion } = req.body;
    
    let user = usuarios.find(usuario => usuario.username == username);
    if(user) return res.json({error: 'El usuario ya existe'})
    let newUser = {
        username,
        password,
        direccion
    }
    usuarios.push(newUser);
    let acces_token = await generateToken(newUser);

    return res.json({acces_token});
});

app.post("/login", async (req, res, next)=>{
    let {username, password } = req.body;

    let user = usuarios.find(usuario => usuario.username == username);
    if(!user) return res.json({error: 'El usuario no existe'});
    
    if(user.password != password) return res.json({error: 'Los datos no coinciden'});
    
    let acces_token = await generateToken(user);

    return res.json({acces_token});
});

async function generateToken(user){
    return await jwt.sign({data:user, fecha: 'Es hoy'}, private_key, {expiresIn: '48h'}  )
}

app.listen(PORT, ()=>{
    console.log(`Server en puerto http://localhost:${PORT}`);
})