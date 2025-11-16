import mongoose from "mongoose";

const Schema = mongoose.Schema;
const ObjectId = mongoose.Types.ObjectId;

const verificationSchema = new Schema({
    name : {type : String , trim : true , required : true },
    email : {type : String , lowercase : true , required : true},
    cid : {type : String , required : true},
    timestamp : {
        type : Date ,
        default : Date.now
    }
});

export default mongoose.model("VerificationModel" , verificationSchema);