
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const User = require('./models/User');

// Config JSON response
app.use(express.json());

// Open Route - Public Route
app.get('/', (req, res) => {
    res.status(200).json({ message: 'Bem vindo a nossa API' });
})

// Private Route
app.get("/user/:id", checkToken, async (req, res) => {

    const id = req.params.id;

    // check if user exists
    const user = await User.findById(id, '-password'); // não mostra a senha do usuário no retorno
    
    if(!user)
    {
        return res.status(404).json({ message: 'Usuário não encontrado!' });
    }

    res.status(200).json({ user });
})

function checkToken(req, res, next) //middleware
{
    const authHeader = req.headers['authorization']; // é o próprio token
    const token = authHeader && authHeader.split(" ")[1]; /* [0] - Bearer
                                                             [1] - Token
                                                             Neste caso, queremos o token
                                                         */
    if(!token)
    {
        return res.status(401).json({ message: 'Acesso negado!' });
    }

    try {

        const secret = process.env.SECRET;
        jwt.verify(token, secret);

        next(); // finaliza o middleware e deixa acessar a rota 
    }
    catch(error)
    {
        console.log(error);
        res.status(400).json({ message: "Token inválido!" });
    }
}


// Register User
app.post('/auth/register', async(req, res) => {

    const {name, email, password, confirmPassword} = req.body;

    // validations
    if(!name)
    {
        return res.status(422).json({ message: 'O nome é obrigatório!' });
    }

    if(!email)
    {
        return res.status(422).json({ message: 'O email é obrigatório!' });
    }

    if(!password)
    {
        return res.status(422).json({ message: 'A senha é obrigatória!' });
    }

    if(password !== confirmPassword)
    {
        return res.status(422).json({ message: 'As senhas não conferem! ' });
    }

    // check if user exists
    const userExists = await User.findOne({ email: email });

    if(userExists)
    {
        return res.status(422).json({ message: 'Por favor, utilize outro e-mail!' });
    }

    // create password
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    // create user
    const user = new User({
        name,
        email,
        password: passwordHash,
    })

    try {
        
        await user.save();
        res.status(200).json({ message: 'Usuário criado com sucesso!' });

    }
    catch(error)
    { 
        console.log(error);
        res.status(500).json({ message: 'Aconteceu um erro no servidor, tente novamente mais tarde!' });
    }

})

// Login User
app.post("/auth/login", async (req, res) => {

    const { email, password } = req.body; // desestruturação

    // validations
    if(!email)
    {
        return res.status(422).json({ message: 'O email é obrigatório!' });
    }

    if(!password)
    {
        return res.status(422).json({ message: 'A senha é obrigatória!' });
    }

    // check if user exists
    const user = await User.findOne({ email: email });

    if(!user)
    {
        return res.status(404).json({ message: 'Usuário não encontrado!' });
    }

    // check if password match
    const checkPassword = await bcrypt.compare(password, user.password);

    if(!checkPassword)
    {
        return res.status(422).json({ message: 'Senha inválida!' });
    }

    try {

        const secret = process.env.SECRET;
        const token = jwt.sign({
            id: user._id,
        }, secret)

        res.status(200).json({ message: "Autenticação realizada com sucesso!", token });
    }
    catch(error)
    { 
        console.log(error);
        res.status(500).json({ message: 'Aconteceu um erro no servidor, tente novamente mais tarde!' });
    }
})

// Conectar com o banco de dados
const dbuser = process.env.DB_USER;
const dbpassword = process.env.DB_PASSWORD;

mongoose.connect(
    `mongodb+srv://${dbuser}:${dbpassword}@cluster0.m7v9yto.mongodb.net/myFirstDatabase?retryWrites=true&w=majority`
)
.then(() => {
    app.listen(3000);
    console.log('Conectamos ao banco!')
})
.catch((err) => { console.log(err) })


