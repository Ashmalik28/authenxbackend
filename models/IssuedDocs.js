import mongoose from "mongoose";

const Schema = mongoose.Schema;

const issuedDocsSchema = new Schema({ 
    personName : {type : String , required : true},
    personWallet : {type : String , required : true},
    docType : {type : String , required : true},
    orgWallet : {type : String , required : true},
    orgName : {type : String , required : true},
    docHash : {type : String , required : true , unique : true},
    issuedAt : {type : Date , default : Date.now},
    valid : {type : Boolean , default : true}
});

export default mongoose.model("issuedDocsModel" , issuedDocsSchema);
