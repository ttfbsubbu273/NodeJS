const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const config = require('config');
const {check, validationResult} = require('express-validator');

const { getUserByEmail, getUserById, updateUser } = require("../../../services/users");
const auth = require('../../../middleware/auth');


router.post("/", 
    [
        check('email', 'Valid email required').isEmail(),
        check('password','Password required').trim().not().isEmpty(),
    ],
    async(req, res) =>{
        const validationErrors = validationResult(req);
        if(!validationErrors.isEmpty()){
            return res.status(400).json({error: validationErrors.array()});
        }
        const userCredentials = req.body;

        const user = getUserByEmail(userCredentials.email);
        if(!user){
            return res.status(400).json({error:[{ message: "Invalid credentials"}]});
        }

        const isMatch = await bcrypt.compare(userCredentials.password, user.password);
        if(!isMatch){
            return res.status(400).json({error: [{ message: 'Invalid credentials'}]});
        }

        const payload = {
            user: {
                email: user.email,
                name: user.name,
                id: user.id
            }
        };
        jwt.sign(payload, config.get('jwtSecret'), {expiresIn: 360000},(err, token) => {
            if(err){
                console.log(err)
            };
            res.status(200).json({token});
        })
    }
)

router.post('/change-password',
    [
        check('old_password','Old password required').trim().not().isEmpty(),
        check('new_password','New password required').trim().not().isEmpty(),
    ], 
    auth, 
    async(req, res) => {
        const validationErrors = validationResult(req);
        if(!validationErrors.isEmpty()){
            return res.status(400).json({error: validationErrors.array()});
        }

        const data = req.body;
        let user = getUserById(req.user.id);

        const isMatch = await bcrypt.compare(data.old_password, user.password);
        if(!isMatch){
            return res.status(400).json({error: [{ message: 'Invalid credentials'}]});
        }

        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(data.new_password, salt);

        if(updateUser(user)){
            return res.status(200).json({ message:`Password for ${user.name} updated`})
        }else{
            return res.status(500).json({ message: "There was an issue changing the password"})
        }

    }
)

module.exports = router;