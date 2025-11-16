import mongoose from "mongoose";

const Schema = mongoose.Schema;
const ObjectId =  mongoose.Types.ObjectId;

const contactPersonSchema = new Schema({
    fullName : {type : String , required : true},
    position : {type : String , required : true},
    contactNo : {type : String , required : true},
    personalEmail : {type : String , required : true}
});

const kycDetailsSchema = new Schema({
    orgName : {type : String , required : true},
    orgType : {type : String , required : true},
    officialEmail : {type : String , required : true},
    website : {type : String},
    address : {type : String , required : true},
    country : {type : String , required : true},
    registrationNo : {type : String , required : true},
    certificateUrl : {type : String},
    contactPerson : {type : contactPersonSchema},
    status : {
        type : String ,
        enum : ["Pending" , "Approved" , "Rejected"],
        default : "Pending"
    }
});

const organizationSchema = new Schema ({
    walletAddress : {type : String , unique : true , required : true},
    nonce : {type : String , default : () => Math.floor(Math.random() * 1000000).toString()},
    kycDetails : {type : kycDetailsSchema},
    iskycVerified : {type : Boolean , default : false},
},{ timestamps: true });

const OrganizationModel = mongoose.model('OrganizationModel' , organizationSchema)

export default OrganizationModel;