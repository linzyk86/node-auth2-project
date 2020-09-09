const express = require("express")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const Users = require("./users-model")
const restrict = require("../middleware/restrict")

const router = express.Router()


router.post("/api/register", async (req, res, next) => {
    try {
        const { username, password } = req.body
        const user = await Users.findBy({ username }).first()

        if (user) {
            return res.status(409).json({
                message: "Username taken",
            })
        }
        const newUser = await Users.add({
            username,
            password: await bcrypt.hash(password, 14),
        })
        res.status(201).json(newUser)
    } catch (err) {
        next(err)
    }
})


router.post("/api/login", async (req, res, next) => {
    try {
        const { username, password } = req.body
        const user = await Users.findBy({ username }).first()

        if (!user) {
            return res.status(401).json({
                message: "invalid credentials",
            })
        }
        const passwordValid = await bcrypt.compare(password, user.password)
        if (!passwordValid) {
            return res.status(401).json({
                message: "Invalid credentials",
            })
        }
        const token = jwt.sign({
            userID: user.id,
            userDepartment: "marketing"
        }, process.env.JWT_SECRET)

        res.json({
            message: `Welcome ${user.username}!`,
            token: token,
        })
    } catch (err) {
        next(err)
    }
})



router.get("/api/users", restrict("membership"), async (req, res, next) => {
    try {
        res.json(await Users.find())
    } catch (err) {
        next(err)
    }
})

module.exports = router