import mongoose from "mongoose";

const transactionSchema = new mongoose.Schema(
  {
    action: {
      type: String,
      required: true,
      enum: [
        "Document Issued",
        "Document Revoked",
        "Organization Approved",
        "Organization Revoked",
      ],
    },

    walletAddress: {
      type: String,
      required: true,
      lowercase: true,
      index: true,
    },

    status: {
      type: String,
      enum: ["Success", "Failed"],
      default: "Success",
    },

    txHash: {
      type: String,
      required: true,
      unique: true,
    },

    blockNumber: {
      type: Number,
      required: true,
    },

    personName: String,

    personWallet: String,

    orgName: String,

    docType: String,

    docHash: String,
  },
  {
    timestamps: true,
  }
);

export default mongoose.model("Transaction", transactionSchema);