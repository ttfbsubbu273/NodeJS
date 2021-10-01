const express = require('express');
const router = express.Router();
const {check, validationResult} = require('express-validator');
const uuid = require("uuid");
const bcrypt = require('bcryptjs');
const multer  = require('multer');
const path = require('path');


const allowedFileTypes = /jpeg|jpg|png|jfif/;
const storage = multer.diskStorage({
    destination: './public/uploads/',
    filename: (req, file, callback) => {
        callback(null, 'profile_picture-'+Date.now()+path.extname(file.originalname));
    },
});
const upload = multer({
    storage: storage,
    fileFilter: (req, file, callback) => {
        const extname = allowedFileTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedFileTypes.test(file.mimetype);
        if(mimetype && extname){
            return callback(null, true);
        }
        else{
            return callback('Only images allowed');
        }
    }
}).single('profile_picture');

const auth = require("../../../middleware/auth");
const { 
    registerUser, 
    updateUser, 
    getUserById, 
    getAllUsers
} = require('../../../services/users');


router.post('/',
    upload,
    [
        check('name','Name is required').trim().not().isEmpty(),
        check('email', 'Enter a valid email id').isEmail(),
        check('phone', 'Enter a valid 10 digit phone number').isLength({min:10, max:10}),
        check('password','Password must have 6 or more characters').isLength({min:6})
    ],
    async (req, res) => {

        await upload(req, res, async err => {
            if (err) {
              return res.status(500).json({error:[{ message: "There was en error with uploading the file"}]})
            } 

            const validationErrors = validationResult(req);
            if(!validationErrors.isEmpty()){
                return res.status(400).json({error: validationErrors.array()});
            }

            const newUser = req.body;

            const salt = await bcrypt.genSalt(10);
            newUser.password = await bcrypt.hash(newUser.password, salt);

            newUser.id = uuid.v4();
            newUser.profile_picture = req.file.filename;

            const result = await registerUser(req.body);
            return res.status(result[1]).json(result[0]);
        })
    }
)

router.get("/", auth, async(req,res) =>{
    
    const user = getUserById(req.user.id);

    if(!user){
        return res.status(400).json({error: [{ message: "There was en error fetching your profile"}]})
    }

    return res.status(200).json({
        "name": user.name,
        "email": user.email,
        "phone": user.phone,
        "profile_picture": user.profile_picture,
        "id": user.id
    });
})

router.get('/users', auth, (req, res) => {
    
    const users = getAllUsers();

    return res.status(200).json(users)
});

router.post('/update', auth, upload, (req, res) => {

    const newData = req.body;
    const currentUser = getUserById(req.user.id);

    if(req.file){
        newData.profile_picture = req.file.filename;
    }

    const updatedUser = {
        "id": currentUser.id,
        "name": newData.name || currentUser.name,
        "email": newData.email || currentUser.email,
        "phone": newData.phone || currentUser.phone,
        "profile_picture": newData.profile_picture || currentUser.profile_picture,
        "password": currentUser.password
    }

    if(updateUser(updatedUser)){
        return res.status(200).json({ message:`User ${updatedUser.name} updated`})
    }else{
        return res.status(500).json({ message: "There was an issue updating the user"})
    }

})

module.exports = router;