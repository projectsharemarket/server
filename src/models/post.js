import mongoose, { Schema } from "mongoose";

const PostSchema = new Schema({
    title: String,
    body: String,
    tags: [String],
    price: Number,
    photo: String,
    productName: String,
    publishedDate: {
        type: Date,
        default: Date.now,
    },
    user: {
        _id: mongoose.Types.ObjectId,
        username: String,
    },
    cost: {
        type: Number,
        default: 0,
    },
    recentPrice: {
        type: Number,
        default: 0,
    },
    quality: {
        type: String,
        default: "제품 상태 측정 중...",
    },
    sold: {
        type: Number,
        default: 0,
    },
    damagedImage: {
        type: String,
        default: "이미지 분석 중...",
    },
    auction: String,
    auctionPrice: {
        type: Number,
        default: 0,
    },
    auctionName: {
        type: String,
        default: "정보 없음",
    },
});

const Post = mongoose.model('Post', PostSchema);
export default Post;
