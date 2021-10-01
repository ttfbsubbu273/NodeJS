const jwt = require('jsonwebtoken');
const config = require('config');

module.exports = function(req, res, next){

    const bearerToken = req.headers.authorization;
    const token = bearerToken.split("-")[1];
    
    if(!token){
        return res.status(401).json({msg: 'No token, access denied.'});
    }

    try{
        const decoded = jwt.verify(token, config.get('jwtSecret'));
        req.user = decoded.user;
        next();
    }catch(err){
        res.status(401).json({msg: 'Token is not valid'});
    }
}

