import express from "express"
import dotenv from "dotenv"
import connectDB from './db.js';
import VerifierModel from './models/Verifier.js';
import OrganizationModel from "./models/Organization.js";
import VerificationModel from "./models/Verification.js";
import issuedDocsModel from "./models/IssuedDocs.js";
import cors from "cors"
import { z} from "zod"
import bcrypt from "bcrypt"
import jwt from "jsonwebtoken"
import authMiddleware from "./middleware/authMiddleware.js";
import {ethers} from "ethers"
import fs from 'fs'
import multer from "multer";
import { PinataSDK } from "pinata";

dotenv.config();

const app = express();

const uploadDir = "uploads";
if(!fs.existsSync(uploadDir)){
   fs.mkdirSync(uploadDir);
}

const storage = multer.diskStorage({
  destination : (req , file , cb) => {
    cb(null , uploadDir);
  },
  filename: (req, file, cb) => {
  const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
  const safeName = file.originalname.replace(/\s+/g, "_").replace(/[^a-zA-Z0-9._-]/g, "");
  cb(null, `${uniqueSuffix}-${safeName}`);
  }
});

const storageMemory = multer.memoryStorage();

const pinata = new PinataSDK({
  pinataJwt: process.env.PINATA_JWT,
  pinataGateway: "yellow-determined-cephalopod-955.mypinata.cloud", 
});



const fileFilter = (req , file , cb) => {
  const allowedTypes = ["application/pdf" , "image/jpeg" , "image/png"];
  if(allowedTypes.includes(file.mimetype)){
    cb(null , true);
  }else {
    cb(new Error("Only Pdf and image files are allowed!"))
  }
};

const uploadMemory = multer({
  storage : storageMemory,
  limits : {fileSize : 10 * 1024 *1024},
  fileFilter
});

const upload = multer({
  storage ,
  limits : {fileSize: 10 * 1024 * 1024},
  fileFilter,
});

app.use("/uploads" , express.static(uploadDir));


app.use(cors({
  origin : "http://localhost:5173"
}))
app.use(express.json());

const SignupSchema = z.object({
  firstName : z.string().min(2 , "First name should contain atleast 2 characters").max(10 , "First name should contain at max 20 characters"),
  lastName : z.string().min(2 , "Last Name should contain atleast 2 characters").max(10 , "Last Name should contain at max 20 characters"),
  email : z.string().email("Invalid email format"),
  password : z.string().min(8 , "Password must be at least 8 characters long")
})

export const OrgKYCSchema = z.object({
  orgName: z.string().min(2, "Organization name must be at least 2 characters").max(50, "Organization name must be at most 50 characters"),
  orgType: z.string().min(2, "Organization type is required"),
  officialEmail: z.string().email("Invalid official email format"),
  website: z.string().url("Invalid website URL").optional().or(z.literal("")),
  address: z.string().min(5, "Registered address must be at least 5 characters"),
  country: z.string().min(2, "Country is required"),
  registrationNo: z.string().min(2, "Registration number is required"),
  certificate: z
  .any()
  .refine(file => file != null, "Certificate file is required")
  .refine(file => file.size <= 10_000_000, "File size must be <= 10 MB")
  .refine(file => ["application/pdf", "image/png", "image/jpeg"].includes(file.mimetype),
          "Only PDF, PNG, or JPEG files are allowed"),
  fullName: z.string().min(2, "Full name must be at least 2 characters").max(50, "Full name must be at most 50 characters"),
  position: z.string().min(2, "Position is required").max(30, "Position must be at most 30 characters"),
  contactNo: z.string().min(5, "Contact number is required"),
  personalEmail: z.string().email("Invalid personal email format"),
});

connectDB();

app.post("/nonce" , async function(req ,res){
  const {walletAddress} = req.body;
  if(!walletAddress){
    return res.status(400).json({msg : "Wallet Address required"})
  }
  try{
    let org = await OrganizationModel.findOne({walletAddress});
    if(!org){
      org = await OrganizationModel.create({
        walletAddress
      })
    }
    res.json({nonce : org.nonce})
  }catch (err) {
    console.error("DB error: " , err.message);
    res.status(500).json({error : "Server error"})
  }
})

app.post("/walletverify" , async function(req,res){
  const {walletAddress , signature} = req.body;
  const org = await OrganizationModel.findOne({walletAddress});
  if(!org){
    return res.status(400).json({msg : "Organization not found"})
  }
  const recovered = ethers.verifyMessage(org.nonce , signature);
  if(recovered.toLowerCase() !== walletAddress.toLowerCase()){
    return res.status(401).json({msg : "Invalid Signature"})
  }
  org.nonce = Math.floor(Math.random() * 1000000).toString();
  await org.save();

  const token = jwt.sign({
    walletAddress : org.walletAddress , id : org._id
  },process.env.JWT_SECRET , {expiresIn : "1h"})

  res.json({token , iskycVerified : org.iskycVerified});
})

app.post("/signup" , async function(req , res){

  const result = SignupSchema.safeParse(req.body);
  
    if(!result.success){
      console.log(result);
      console.log(result.error.issues);
      const errors = result.error.issues.map((e) => ({
        field : e.path,
        message : e.message
      }));
      return res.status(400).json({errors});
    }
    try{
      
      const saltRounds = 10 ;
      const hashedPassword = await bcrypt.hash(result.data.password , saltRounds);
    
      await VerifierModel.create({
        ...result.data , 
        password : hashedPassword,
      });
      res.json({
      message : "You have Signed up"
    });
    } catch (err){
    console.error("DB error: " , err.message);
    res.status(500).json({error : "Server error"})
  }
});

app.post("/signin" , async function(req , res){
  const {email , password } = req.body;

  try{
    const user = await VerifierModel.findOne({
      email
    })
    if(!user){
      return res.status(400).json({
        error : "Invalid email or Password"
      })
    }
    const isMatch = await bcrypt.compare(password , user.password);
    if(!isMatch){
      res.status(400).json({error : "Invalid email or Password"})
    }

    const token = jwt.sign({
      id : user._id , email : user.email
    }, process.env.JWT_SECRET , {expiresIn : "1h"});

    res.json({message : "Login Successful" , token });

  }catch (err){
    console.log("DB Error" , err.message);
    res.status(500).json({error : "Server Error"});
  }
     
})

app.post("/upload", uploadMemory.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "No file uploaded" });

    const blob = new Blob([req.file.buffer], { type: req.file.mimetype });
    const file = new File([blob], req.file.originalname, { type: req.file.mimetype });

    const uploadResponse = await pinata.upload.private.file(file);

    res.json({
      success: true,
      message: "✅ File uploaded successfully",
      data: uploadResponse,
    });
  } catch (error) {
    console.error("❌ Upload failed:", error);
    res.status(500).json({ error: "Upload failed", details: error.message });
  }
});

app.get("/view/:cid", authMiddleware, async (req, res) => {
  try {
    const { cid } = req.params;

    if (!cid) {
      return res.status(400).json({ success: false, message: "CID is required" });
    }

    const accessLink = await pinata.gateways.private.createAccessLink({
      cid,
      expires: 30, 
    });

    res.json({
      success: true,
      url: accessLink,
      expiresIn: "60 seconds",
    });
  } catch (error) {
    console.error("❌ Error creating access link:", error);
    res.status(500).json({
      success: false,
      message: "Failed to create access link",
      error: error.message,
    });
  }
});


app.get("/kycrequests", authMiddleware, async (req, res) => {
  try {
    const OWNER_WALLET = "0x03034f8896c807b5077ABE110e1a9C7e8358ba50".toLowerCase();

    if (!req.user.walletAddress || req.user.walletAddress.toLowerCase() !== OWNER_WALLET) {
      return res.status(403).json({ error: "Access denied: Only owner can access this route" });
    }

    const requests = await OrganizationModel.find({ "kycDetails.status": "Pending" });

    res.json({ success: true, requests });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/updateOrgStatus', async (req, res) => {
    try {
        const { walletAddress, status } = req.body;

        if (!walletAddress || !status) {
            return res.status(400).json({ success: false, message: "Missing required fields" });
        }

        if (!["Approved", "Rejected"].includes(status)) {
            return res.status(400).json({ success: false, message: "Invalid status" });
        }

        const org = await OrganizationModel.findOne({ walletAddress });

        if (!org) {
            return res.status(404).json({ success: false, message: "Organization not found" });
        }

        const updatedOrg = await OrganizationModel.findOneAndUpdate(
        { walletAddress },
        {
        $set: {
            "kycDetails.status": status,
            iskycVerified: status === "Approved"
        }
    },
    { new: true, runValidators: true }
);


        res.json({ success: true, message: `Organization ${status.toLowerCase()} successfully` , data : updatedOrg });

    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, message: "Server error" });
    }
});

app.get("/me", authMiddleware, async (req, res) => {
  try {
    const org = await OrganizationModel.findOne({ walletAddress: req.user.walletAddress });
    if (!org) {
      return res.status(404).json({ success: false, message: "Organization not found" });
    }
    res.json({ success: true, kycDetails: org.kycDetails });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post("/verify" , authMiddleware , async function(req,res){
  try{
    let user = await VerifierModel.findById(req.user.id).select("-password");
    if (!user) {
      user = await OrganizationModel.findById(req.user.id).select("-password");
    }

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const {name , email , cid} = req.body;

    if(!name || !email || !cid){
      return res.status(400).json({error : "All fields (name, email, cid) are required when submitting a form"});
    }

    const newVerification = new VerificationModel({
      name , email , cid , timestamp : new Date()
    })

    await newVerification.save();

    res.status(201).json({
      message: "Verification details stored successfully",
      data: newVerification,
    });


  }catch (err) {
    console.log("DB error" , err.message);
    res.status(500).json({error : "Server error"});
  }
});

app.get("/dashboard" , authMiddleware , async function(req,res){
  try{
    const user = await VerifierModel.findById(req.user.id).select("-password");
    if(!user){
      return res.status(404).json({error : "User not found"});
    }
    res.json({message : "Token valid" , user});
  }catch (err) {
    console.log("DB error" , err.message);
    res.status(500).json({error : "Server error"});
  }
});

app.post("/issue", authMiddleware, async (req, res) => {
  try {
    const {
      personName,
      personWallet,
      docType,
      orgWallet,
      orgName,
      docHash,
    } = req.body;

    let user = await VerifierModel.findById(req.user.id).select("-password");
    if (!user) {
      user = await OrganizationModel.findById(req.user.id).select("-password");
    }

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const existingDoc = await issuedDocsModel.findOne({ docHash });
    if (existingDoc) {
      return res.status(400).json({ error: "Document already issued" });
    }

    const issuedDoc = new issuedDocsModel({
      personName,
      personWallet,
      docType,
      orgWallet,
      orgName,
      docHash,
    });

    await issuedDoc.save();

    res.status(201).json({
      message: "Document issued successfully",
      issuedDoc,
    });
  } catch (err) {
    console.error("DB error:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/getWallet" , authMiddleware , async (req , res) => {
  try {
    const {docHash} = req.body;
    let doc = await issuedDocsModel.findOne({docHash});
    if(!doc){
      return res.status(401).json({error : "No wallet address available"})
    }
    return res.status(200).json({
      message : "Wallet address found" ,
      walletAddress : doc.personWallet
    })
  }catch (err){
    console.log("DB error" , err.message);
    res.status(500).json({error : "Server error"});
  }
})

app.get("/dashboard-stats", async (req, res) => {
  try {
    const totalDocuments = await issuedDocsModel.countDocuments({ valid: true });
    const totalVerifications = await VerificationModel.countDocuments();
    const totalVerifiedOrgs = await OrganizationModel.countDocuments({ "kycDetails.status": "Approved" });

    res.json({
      success: true,
      data: {
        totalDocuments,
        totalVerifications,
        totalVerifiedOrgs
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post("/kyc", authMiddleware, upload.single("certificate"), async (req, res) => {
  try {
    const org = await OrganizationModel.findById(req.user.id);
    if (!org) {
      return res.status(404).json({ error: "Organization not found" });
    }

    let website = req.body.website || "";

    if (website && !/^https?:\/\//i.test(website)) {
    website = "https://" + website; 
    }

    const payload = {
      ...req.body,
      website ,
      certificate: req.file
    };

    const validatedData = OrgKYCSchema.safeParse(payload);
    if (!validatedData.success) {
    return res.status(400).json({ errors: validatedData.error.issues });
    }

    const fileUrl = `${req.protocol}://${req.get("host")}/uploads/${req.file.filename}`;

    const updatedOrg = await OrganizationModel.findOneAndUpdate(
      { walletAddress: req.user.walletAddress },
      {
        kycDetails: {
          orgName: validatedData.data.orgName,
          orgType: validatedData.data.orgType,
          officialEmail: validatedData.data.officialEmail,
          website: validatedData.data.website,
          address: validatedData.data.address,
          country: validatedData.data.country,
          registrationNo: validatedData.data.registrationNo,
          certificateUrl: fileUrl,
          contactPerson: {
            fullName: validatedData.data.fullName,
            position: validatedData.data.position,
            contactNo: validatedData.data.contactNo,
            personalEmail: validatedData.data.personalEmail
          },
          status: "Pending"
        },
        iskycVerified: false
      },
      { new: true }
    );

    res.json({ success: true, message: "KYC submitted successfully!", data: updatedOrg });
  } catch (err) {
    if (err instanceof z.ZodError) {
      return res.status(400).json({ errors: err.errors });
    }
    if (err instanceof multer.MulterError && err.code === "LIMIT_FILE_SIZE") {
      return res.status(400).json({ success: false, message: "File size should not exceed 10 MB" });
    }
    console.log("DB error", err.message);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/check-user-type", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id; 

    if (!userId) {
      return res.status(400).json({ success: false, message: "User ID missing in token" });
    }

    const org = await OrganizationModel.findById(userId);
    if (org) {
      return res.status(200).json({
        success: true,
        type: "organization",
        name: org.kycDetails?.orgName || org.name || "Unnamed Organization",
      });
    }

    const verifier = await VerifierModel.findById(userId);
    if (verifier) {
      return res.status(200).json({
        success: true,
        type: "verifier",
        name: verifier.firstName,
        email : verifier.email
      });
    }

    res.status(200).json({
      success: true,
      type: "normal",
      name: "Guest User",
    });

  } catch (error) {
    console.error("Error checking user type:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});


app.get("/auth/check" , authMiddleware , (req , res) => {
  res.json({valid : true});
});


app.listen(process.env.PORT, () => {
  console.log(`Server running on port ${process.env.PORT}`);
});