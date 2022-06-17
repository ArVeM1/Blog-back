import bckrypt from "bcrypt";
import UserModel from "../models/User.js";
import jwt from "jsonwebtoken";

export const register = async (req, res) => {
  try {
    const password = req.body.password;
    const salt = await bckrypt.genSalt(10)
    const hash = await bckrypt.hash(password, salt) // Секретим пароль

    const doc = new UserModel({ // создаем doc в БД
      email: req.body.email,
      fullName: req.body.fullName,
      avatarUrl: req.body.avatarUrl,
      passwordHash: hash,
    });

    const user = await doc.save(); // сохраняем в БД

    const token = jwt.sign({ // делаем token (в токене хранится вся информация)
      _id: user._id,
    }, 'secret123', {
      expiresIn: '30d'
    })

    const {passwordHash, ...userData} = user._doc // вытаскиваем информацию о пользоваетеле, выкидываем пароль

    res.json({...userData, token}) // отправляем клиенту
  } catch (e) {
    res.status(500).json({
      message: 'Не удалось зарегестрироваться'
    })
  }
}

export const login = async (req, res) => {
  try {
    const user = await UserModel.findOne({email: req.body.email}) // Найди в БД email

    if (!user) {
      return res.status(404).json({
        message: 'Пользователь не найден', // Нивкоем случае не пиши это для бэка!!!
      })
    }

    const isValidPass = await bckrypt.compare(req.body.password, user._doc.passwordHash) // если эти 2 строки сходятся

    if (!isValidPass) {
      return res.status(400).json({
        message: 'Неверный логин или пароль',
      })
    }

    const token = jwt.sign({ // делаем token (в токене хранится вся информация)
      _id: user._id,
    }, 'secret123', {
      expiresIn: '30d'
    })

    const {passwordHash, ...userData} = user._doc // вытаскиваем информацию о пользоваетеле, выкидываем пароль

    res.json({...userData, token}) // отправляем клиенту

  } catch (e) {
    res.status(500).json({
      message: 'Не удалось авторизоваться'
    })
  }
}

export const getMe = async (req, res) => {
  try {
    const user = await UserModel.findById(req.userId)

    if (!user) {
      return res.status(404).json({
        message: 'Пользователь не найден'
      })
    }

    const {passwordHash, ...userData} = user._doc // вытаскиваем информацию о пользоваетеле, выкидываем пароль

    res.json({...userData}) // отправляем клиенту

  } catch (e) {
    res.status(500).json({
      message: 'Нет доступа'
    })
  }
}