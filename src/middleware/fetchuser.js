let jwt=require('jsonwebtoken');
const JWT_SECRET= 'Samisagoodboy';
const fetchuser = (req,res,next)=>{
    //Get the user from the jwt token and add it to the req object
    const token=req.header('auth-token');
    if(!token){
        req.status(401).send({error: "Please Authenticate using a valid token"})
    }
    try{
        const data = jwt.verify(token, JWT_SECRET);
        req.user=data.user;
        next();
    } catch(error){
        req.status(401).send({error: "Please Authenticate using a valid token"})
    }
}
module.exports = fetchuser;