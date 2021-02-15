const jwt = require("jsonwebtoken")

function restrict(department){
    const departments = ["marketing", "accounting", "membership"]

    return async(req, res, next)=>{
        const authError = {
            message:"Invalid credentials",
        }
        try{
            const token = req.headers.authorization
            if(!token){
                return res.status(401).json(authError)
            }
            jwt.verify(token, process.env.JWT_SECRET, (err, decoded)=>{
                if(err){
                    return res.status(401).json(authError)
                }
                console.log(department, decoded.userDepartment)
                if(department && departments.indexOf(decoded.userDepartment)
                >departments.indexOf(department)){
                    res.status(403).json({
                        message: "not allowed",
                    })
                }
                req.token = decoded
                next()
            })
        } catch(err){
            next(err)
        }
    }
}

module.exports = restrict