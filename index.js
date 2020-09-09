const express = require("express")
const session = require("express-session")
const usersRouter = require("./users/users-router")

const server = express()
const port = process.env.PORT || 8080


server.use(express.json())
server.use(session({
	resave: false, // avoid recreating sessions that have not changed
	saveUninitialized: false, // comply with GDPR laws for setting cookies automatically
	secret: process.env.JWT_SECRET, // cryptographically sign the cookie
}))

server.use(usersRouter)
server.use((err, req, res, next) => {
	console.log(err)
	
	res.status(500).json({
		message: "Something went wrong",
	})
})

server.listen(port, () => {
	console.log(`Running at http://localhost:${port}`)
})
