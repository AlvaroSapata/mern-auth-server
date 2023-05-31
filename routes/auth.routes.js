const User = require("../models/user.model.js");

const router = require("express").Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const isAuthenticated = require("../middlewares/isAuthenticated.js")

// POST "/api/auth/signup" => Registrar al usuario
router.post("/signup", async (req, res, next) => {
  console.log(req.body);

  const { username, email, password } = req.body;

  // Validaciones de Server

  if (!username || !email || !password) {
    res.status(400).json({ errorMessage: "Debes rellenar todos los campos" });
    return; // Detener el resto de la ejecucion
  }

  // Podriamos hacer validaciones de contraseña, correo, etc ...
  //! Tenemos que hacerlas en el proyecto

  // Si el usuario ya esta registrado => modelo => DB
  try {
    const foundUser = await User.findOne({ email: email });
    if (foundUser) {
      res.status(400).json({ errorMessage: "Usuario ya registrado" });
      return;
    }

    // Encriptar la contraseña
    const salt = await bcrypt.genSalt(10);
    const hashPassword = await bcrypt.hash(password, salt);
    console.log(hashPassword);

    // Crear nuevo elemento de usuario
    await User.create({
      username,
      email,
      password: hashPassword,
    });
    res.json("Usuario creado");
  } catch (error) {
    next(error);
  }
});

// POST "/api/auth/login" => Validar las credenciales del usuario
router.post("/login", async (req, res, next) => {
  console.log(req.body);
  const { email, password } = req.body;

  // Validaciones, campos llenos etc ...

  try {
    // Usuario existe en la DB
    const foundUser = await User.findOne({ email: email });
    if (!foundUser) {
      res
        .status(400)
        .json({ errorMessage: "Usuario no registrado con ese correo" });
      return;
    }

    // Password valido
    const isPasswordCorrect = await bcrypt.compare(
      password,
      foundUser.password
    );
    if (!isPasswordCorrect) {
      res.status(400).json({ errorMessage: "Contraseña incorrecta" });
      return;
    }

    // ... Si estuviesemos en M2 configurariamos sesions y sesiones activas

    // Crear un token y enviarselo al cliente

    // 1. Creamos el payload
    const payload = {
      _id: foundUser._id,
      email: foundUser.email,
      //* aqui pasariamos los ROLES
      // rol: foundUser.rol
    };

    // 2. Creamos el token
    const authToken = jwt.sign(payload, process.env.TOKEN_SECRET, {
      algorithm: "HS256",
      expiresIn: "7d",
    });
    // 3. enviamos el token al FE

    res.json({ authToken: authToken });
  } catch (error) {
    next(error);
  }
});

// GET "/api/auth/verify" => Indicar al FE si el usuario esta logueado (validar)
router.get("/verify", isAuthenticated, (req, res, next) => {
  // 1. Recibir y validar el token (middleware)
  // 2. Extraer el payload para indicar al Fe quien es el usuario de ese token

  //* Cuando usemos el middleware isAuthenticated tendremos acceso a saber QUIEN es el usuario haciendo la llamada (igual que req.session.user) a traves de req.payload
  console.log("Usuario activo", req.payload)

  res.json({payload: req.payload})
});

module.exports = router;
