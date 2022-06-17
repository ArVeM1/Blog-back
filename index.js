import express from 'express';
import fs from 'fs';
import mongoose from 'mongoose';
import multer from 'multer';
import cors from 'cors';

import { loginValidation, postCreateValidation, registerValidation } from './validations.js'
import { checkAuth, handleValidationErrors } from './utils/index.js'
import { UserController, PostController } from './controllers/index.js';

mongoose.connect('mongodb+srv://admin:wwwwww@cluster0.wezw4.mongodb.net/blog?retryWrites=true&w=majority')
  .then(() => {
    console.log('DB OK')
  })
  .catch((e) => {
    console.log(`DB error ${e}`);
  })

const app = express();

const storage = multer.diskStorage({
  destination: (_, __, cb) => {
    if (!fs.existsSync('uploads')) {
      fs.mkdirSync('uploads');
    }
    cb(null, 'uploads');
  },
  filename: (_, file, cb) => {
    cb(null, file.originalname);
  },
});

const upload = multer({storage}) // создали хранилище

app.use(express.json()); // Разрешаем переводить в json-формат
app.use('/uploads', express.static('uploads')); //проверяем есть ли нужный файл в данной папке
app.use(cors())

app.post('/auth/login', loginValidation, handleValidationErrors, UserController.login);
app.post('/auth/register', registerValidation, handleValidationErrors, UserController.register);
app.get('/auth/me', checkAuth, UserController.getMe);

app.post('/upload', checkAuth, upload.single('image'), (req, res) => {
  res.json({
    url: `/uploads/${req.file.originalname}`
  })
})

app.get('/tags', PostController.getLastTags)

app.get('/posts', PostController.getAll)
// app.get('/posts/tags', PostController.getLastTags)
app.get('/posts/:id', PostController.getOne)
app.post('/posts', checkAuth, postCreateValidation, handleValidationErrors, PostController.create);
app.delete('/posts/:id', checkAuth, PostController.remove);
app.patch('/posts/:id', checkAuth, postCreateValidation, handleValidationErrors, PostController.update)

app.listen(4444, (err) => {
  if (err) {
    return console.log(err)
  }
  console.log('server OK')
})