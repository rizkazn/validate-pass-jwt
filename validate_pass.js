const auth = {}
const model = require("../models/users")
const bcr = require("bcrypt")
const jwt = require("jsonwebtoken")
const response = require("../helpers/response")
const Logger = require("../helpers/logger")

const token = async (email) => {
    try {
        const payload = {
            user: email,
            roles: 'customer',
        }
        const token = jwt.sign(payload, process.env.JWT_KEYS, {expiresIn: "1d" })
        // console.log(token)
        const result = {
            message: "Token Created, Login Success",
            token: token,
            email,
        }
        return result
    } catch (error) {
        throw error // melempar ke function yang memanggil
    }
}

auth.login = async (req, res) => {
    try {
        const passDB = await model.getUserByEmail(req.body.email)
        const passUsers = req.body.password

        if (passDB.length <= 0) {
            return response(res, 200, { msg: "Email Not Registered" })
        }

        const check = await bcr.compare(passUsers, passDB[0].password)
        // console.log(passDB)
        if (check) {
            const result = await token(req.body.email)
            return response(res, 200, result)
        } else {
            return response(res, 401, { msg: "Login Failed!" })
        }
    } catch (error) {
        Logger.error(error)
        return response(res, 500, error, true)
    }
}
// console.log(auth)
module.exports = auth