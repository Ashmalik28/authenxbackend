import jwt from "jsonwebtoken"

export const authMiddleware = (req , res , next) => {
    let token = req.headers.authorization;
    if(token?.startsWith("Bearer ")){
        token = token.split(" ")[1];
    }
    if(!token){
        return res.status(401).json({error : "No token Provided"});
    }
    try{
      const decoded = jwt.verify(token , process.env.JWT_SECRET);
      req.user = decoded;
      next();
    }catch(err) {
        return res.status(401).json({error : "Invalid or expired token"})
    }
}

export default authMiddleware;