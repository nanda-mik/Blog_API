const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const path = require('path');
const multer = require('multer');
const uuidv4 = require('uuidv4');
dotenv.config();

const feedRoutes = require('./routes/feed');

const MONGODB_URI = process.env.MONGODB_URI;

const app = express();

const storage = multer.diskStorage({
    destination: function(req, file, cb) {
        cb(null, 'images');
    },
    filename: function(req, file, cb) {
        cb(null, file.filename + '-' + file.originalname)
    }
});

const fileFilter = (req, file, cb) => {
    if(
        file.mimetype === 'image/png' ||
        file.mimetype === 'image/jpeg'
    ){
        cb(null, true);
    }else{
        cb(null, false);
    }
}


app.use(bodyParser.json());
app.use(
    multer({storage: storage, fileFilter: fileFilter}).single('image')
);
app.use('/images',express.static(path.join(__dirname,'images')));

app.use((req,res,next)=>{
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PATCH,PUT,DELETE');
    res.setHeader('Access-Control-Allow-Headers','Content-Type,Authorization');
    next();
})

app.use('/feed', feedRoutes);

app.use((error, req, res, next) => {
    console.log(err);
    const status = error.statusCode || 500;
    const message = error.message;
    res.status(status).json({message: message});
})

mongoose.connect(MONGODB_URI, { useNewUrlParser: true })
    .then(res => {
        console.log('db connected');
        app.listen(8080);
})
.catch(err => console.log(err));