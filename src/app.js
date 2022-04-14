const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const User = require('./models/User');

dotenv.config()

const app = express();
app.use(express.json());

app.get('/', (req, res) => {
    return res.send({teste: 'teste'})
});

function checkToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(" ")[1];

    if(!token) {
        return res.status(401).json({msg: 'Acesso negado!'});
    }

    try {
        const secret = process.env.SECRET;
        jwt.verify(token, secret);

        next();
    } catch {
        res.status(400).json({msg: 'token inválido'})
    }
}

app.get('/user/:id', checkToken, async (req, res) => {
    const { id } = req.params;

    const user = await User.findById(id, '-password');

    if(!user) {
        return res.status(404).json({error: 'usuario não encontrado'})
    }

    return res.json(user)
});

app.post('/auth/register', async (req, res) => {
    const { name, email, password, confirmpassword } = req.body;
    if(!name) {
        return res.status(422).json({error: 'O nome é obrigatório'})
    }

    if(!email) {
        return res.status(422).json({error: 'O email é obrigatório'})
    }
    if(!password) {
        return res.status(422).json({error: 'A senha é obrigatório'})
    }

    if(password !== confirmpassword) {
        return res.status(422).json({error: 'senhas não conferem'})
    }

    const userExists = await User.findOne({email: email});

    if(userExists) {
        return res.status(422).json({error: 'usuário já cadastrado'})
    }
    
    //cria senha
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    const user = new User({
        name,
        email,
        password: passwordHash,
    });
    try {
        await user.save();
        res.status(201).json({msg: 'usuario criado'})
    } catch(error) {
        return res.status(500).json({msg: error})
    }
});

app.post('/auth/login', async (req, res) => {
    const {email, password} = req.body;

    if(!email) {
        return res.status(422).json({error: 'O email é obrigatório'})
    }
    if(!password) {
        return res.status(422).json({error: 'A senha é obrigatório'})
    }

    const user = await User.findOne({ email: email});

    if(!user){
        return res.status(404).json({error: 'usuario nao cadastrado'})
    }

    const checkPassword = await bcrypt.compare(password, user.password);

    if(!checkPassword){
        return res.status(422).json({error: 'senha invalida'})
    }

    try {
        const secret = process.env.SECRET;
        const token = jwt.sign({
            id: user._id,
        }, secret);

        res.status(200).json({msg: 'Autenticação com sucesso', token});

    } catch (error) {
        res.status(500).json({error: 'erro'})
    }

})

mongoose
    .connect(
        `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASSWORD}@${process.env.DB_NAME}.5d1qp.mongodb.net/${process.env.DB}?retryWrites=true&w=majority`
    )
    .then(() => {
        app.listen(3333);
    });