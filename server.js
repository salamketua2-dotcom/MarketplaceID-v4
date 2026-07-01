require("dotenv").config();

console.log("DATABASE_URL =", process.env.DATABASE_URL ? "ADA" : "TIDAK ADA");

const express = require("express");
const session = require("express-session");
const cors = require("cors");
const path = require("path");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const cloudinary = require("./config/cloudinary");
const streamifier = require("streamifier");
const fs = require("fs-extra");

/* =========================
   DATABASE
========================= */

const db = require("./database/postgres/db");

const authDB = require("./database/postgres/auth");
const productDB = require("./database/postgres/products");
const favoriteDB = require("./database/postgres/favorites");
const followDB = require("./database/postgres/follows");
const chatDB = require("./database/postgres/chats");
const orderDB = require("./database/postgres/orders");
const notificationDB = require("./database/postgres/notifications");
const reviewDB = require("./database/postgres/reviews");
const reportDB = require("./database/postgres/reports");
const verificationDB = require("./database/postgres/verifications");
const offerDB = require("./database/postgres/offers");
const appealDB = require("./database/postgres/appeals");
const locationDB = require("./database/postgres/locations");
const adminDB = require("./database/postgres/admin");

const app = express();

const PORT = process.env.PORT || 3000;

const typingUsers = {};

fs.ensureDirSync("./uploads");
fs.ensureDirSync("./uploads/products");
fs.ensureDirSync("./uploads/profiles");
fs.ensureDirSync("./uploads/verifications");
fs.ensureDirSync("./uploads/temp");

/* =========================
   MIDDLEWARE
========================= */
app.use(express.static(path.join(__dirname,"public")));

app.use(cors({

  origin:true,

  credentials:true

}));

app.use(express.json({

  limit:"50mb"

}));

app.use(express.urlencoded({

  extended:true,

  limit:"50mb"

}));

app.use(session({

  secret:
  process.env.SESSION_SECRET,

  resave:false,

  saveUninitialized:false,

  cookie:{

    httpOnly:true,

    sameSite:"lax",

    secure:false,

    maxAge:
    1000*60*60*24*7

  }

}));

/* =========================
   STATIC
========================= */

app.use(
"/public",
express.static(
path.join(
__dirname,
"public"
)
)
);

app.use(
"/uploads",
express.static(
path.join(
__dirname,
"uploads"
)
)
);

/* =========================
   UPDATE LAST ACTIVE
========================= */

app.use(async(req,res,next)=>{

try{

if(req.session.userId){

await authDB.updateLastActive(
req.session.userId
);

}

}catch(err){

console.log(err);

}

next();

});

/* =========================
   REQUIRE LOGIN
========================= */

function requireLogin(
req,
res,
next
){

if(!req.session.userId){

return res.status(401).json({

success:false,

message:"Login diperlukan"

});

}

next();

}

/* =========================
   REQUIRE ADMIN
========================= */

async function requireAdmin(
req,
res,
next
){

try{

const user=
await authDB.getUserById(
req.session.userId
);

if(!user){

return res.status(401).json({

success:false

});

}

if(

user.role!=="admin"

&&

user.role!=="owner"

){

return res.status(403).json({

success:false,

message:"Akses ditolak"

});

}

req.user=user;

next();

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}

/* =========================
   MULTER PRODUCT
========================= */

const productStorage=
multer.diskStorage({

destination(req,file,cb){

cb(
null,
"./uploads/products"
);

},

filename(req,file,cb){

cb(

null,

Date.now()

+"-"

+Math.random()

.toString(36)

.substring(2)

+path.extname(
file.originalname
)

);

}

});

const uploadProduct = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024
  }
});

/* =========================
   MULTER PROFILE
========================= */

const uploadProfile = multer({
  storage: multer.memoryStorage()
});

/* =========================
   MULTER CHAT
========================= */

const chatStorage=
multer.diskStorage({

destination(req,file,cb){

cb(
null,
"./uploads/chat"
);

},

filename(req,file,cb){

cb(

null,

Date.now()

+"-"

+Math.random()

.toString(36)

.substring(2)

+path.extname(
file.originalname
)

);

}

});

const uploadChat=
multer({

storage:chatStorage

});

/* =========================
   REGISTER
========================= */

app.post(
"/api/register",
async(req,res)=>{

try{

const{

username,
email,
password

}=req.body;

if(
!username||
!email||
!password
){

return res.json({

success:false,

message:"Semua field wajib diisi"

});

}

const exists=
await authDB.userExists(
username,
email
);

if(exists){

return res.json({

success:false,

message:"Username atau Email sudah digunakan"

});

}

const user=
await authDB.registerUser({

username,
email,
password

});

req.session.userId=user.id;

res.json({

success:true,

user

});

}catch(err){

console.log(err);

res.status(500).json({

success:false,

message:err.message

});

}

}
);

/* =========================
   LOGIN
========================= */

app.post(
"/api/login",
async(req,res)=>{

try{

const{

login,
password

}=req.body;

const user=
await authDB.findUser(
login
);

if(!user){

return res.json({

success:false,

message:"Akun tidak ditemukan"

});

}

if(user.blocked){

return res.json({

success:false,

message:"Akun diblokir"

});

}

const match=
await bcrypt.compare(
password,
user.password
);

if(!match){

return res.json({

success:false,

message:"Password salah"

});

}

req.session.userId=user.id;

await authDB.updateLastActive(
user.id
);

res.json({

success:true,

user:{

id:user.id,
username:user.username,
email:user.email,
avatar:user.avatar,
verified:user.verified,
role:user.role

}

});

}catch(err){

console.log(err);

res.status(500).json({

success:false,

message:err.message

});

}

}
);

/* =========================
   LOGOUT
========================= */

app.post(
"/api/logout",
(req,res)=>{

req.session.destroy(()=>{

res.json({

success:true

});

});

}
);

/* =========================
   ME
========================= */

app.get(
"/api/me",
requireLogin,
async(req,res)=>{

try{

const user=
await authDB.getUserById(
req.session.userId
);

res.json({

success:true,

user

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   UPDATE PROFILE
========================= */

app.put(
"/api/profile",
requireLogin,
async(req,res)=>{

try{

const user=
await authDB.updateProfile(

req.session.userId,

req.body

);

res.json({

success:true,

user

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   UPDATE USERNAME
========================= */

app.put(
"/api/profile/username",
requireLogin,
async(req,res)=>{

try{

const{

username

}=req.body;

const user=
await authDB.updateUsername(

req.session.userId,

username

);

res.json({

success:true,

user

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   UPLOAD AVATAR
========================= */

app.post(
"/api/profile/avatar",

requireLogin,

uploadProfile.single(
"avatar"
),

async(req,res)=>{

try{

const result = await new Promise((resolve,reject)=>{
  const stream = cloudinary.uploader.upload_stream(
    {
      folder:"MarketplaceID/profiles"
    },
    (error,result)=>{
      if(error) reject(error);
      else resolve(result);
    }
  );

  streamifier.createReadStream(req.file.buffer).pipe(stream);
});

const avatar = result.secure_url;

const user=
await authDB.updateAvatar(

req.session.userId,

avatar

);

res.json({

success:true,

avatar:user.avatar

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   SAVE LOCATION
========================= */

app.post(
"/api/location",
requireLogin,
async(req,res)=>{

try{

const{

latitude,
longitude,
address

}=req.body;

const location=
await locationDB.saveLocation({

userId:req.session.userId,

latitude,

longitude,

address

});

res.json({

success:true,

location

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   GET LOCATION
========================= */

app.get(
"/api/location",
requireLogin,
async(req,res)=>{

try{

const location=
await locationDB.getLocation(
req.session.userId
);

res.json({

success:true,

location

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   HOME FEED
========================= */

app.get(
"/api/home",
async(req,res)=>{

try{

const data=
await productDB.getHomeProducts();

res.json({

success:true,

latest:data.latest,

recommend:data.recommend

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   CREATE PRODUCT
========================= */

app.post(
"/api/products",

requireLogin,

uploadProduct.array(
"images",
10
),

async(req,res)=>{

console.log("UPLOAD ROUTE TERPANGGIL");

try{

console.log("=== CREATE PRODUCT ===");
console.log(req.body);
console.log(req.files);

const images = [];

if (req.files && req.files.length) {

  for (const file of req.files) {

    const uploaded = await new Promise((resolve, reject) => {

      const uploadStream = cloudinary.uploader.upload_stream(
        {
          folder: "MarketplaceID/products"
        },
        (err, result) => {

          if (err) return reject(err);

          resolve(result);

        }
      );

      streamifier
        .createReadStream(file.buffer)
        .pipe(uploadStream);

    });

    images.push(uploaded.secure_url);

  }

}

const product=
await productDB.createProduct({

sellerId:req.session.userId,

title:req.body.title,

description:req.body.description,

category:req.body.category,

price:req.body.price,

oldPrice:req.body.oldPrice,

location:req.body.location,

latitude:req.body.latitude,

longitude:req.body.longitude,

images

});

res.json({

success:true,

product

});

}catch(err){

console.log(err);

res.status(500).json({

success:false,

message:err.message

});

}

}
);

/* =========================
   PRODUCT DETAIL
========================= */

app.get(
"/api/products/:id",
async(req,res)=>{

try{

const product=
await productDB.getProduct(
req.params.id
);

if(!product){

return res.status(404).json({

success:false,

message:"Produk tidak ditemukan"

});

}

res.json({

success:true,

product

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   MY PRODUCTS
========================= */

app.get(
"/api/my-products",

requireLogin,

async(req,res)=>{

try{

const products=
await productDB.getMyProducts(
req.session.userId
);

res.json({

success:true,

products

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   UPDATE PRODUCT
========================= */

app.put(
"/api/products/:id",

requireLogin,

async(req,res)=>{

try{

console.log("BODY:", req.body);
console.log("USER:", req.session.userId);

const product=
await productDB.updateProduct(

req.params.id,

req.session.userId,

req.body

);

console.log("HASIL:", product);

if(!product){

return res.status(404).json({

success:false,

message:"Produk tidak ditemukan"

});

}

res.json({

success:true,

product

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   UPDATE PRODUCT IMAGES
========================= */

app.put(
"/api/products/:id/images",

requireLogin,

uploadProduct.array(
"images",
10
),

async(req,res)=>{

try{

const images = [];

if(req.files && req.files.length){

for(const file of req.files){

const uploaded = await new Promise((resolve,reject)=>{

const uploadStream = cloudinary.uploader.upload_stream(

{

folder:"MarketplaceID/products"

},

(err,result)=>{

if(err) return reject(err);

resolve(result);

}

);

streamifier
.createReadStream(file.buffer)
.pipe(uploadStream);

});

images.push(uploaded.secure_url);

}

}

const product=
await productDB.updateImages(

req.params.id,

req.session.userId,

images

);

res.json({

success:true,

product

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   DELETE PRODUCT
========================= */

app.delete(
"/api/products/:id",

requireLogin,

async(req,res)=>{

try{

const product=
await productDB.deleteProduct(

req.params.id,

req.session.userId

);

res.json({

success:true,

product

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   SOLD PRODUCT
========================= */

app.put(
"/api/products/:id/sold",

requireLogin,

async(req,res)=>{

try{

const product=
await productDB.soldProduct(

req.params.id,

req.session.userId

);

res.json({

success:true,

product

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   SEARCH
========================= */

app.get(
"/api/search",
async(req,res)=>{

try{

const keyword=
req.query.q || "";

const products=
await productDB.search(
keyword
);

res.json({

success:true,

products

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   CATEGORY
========================= */

app.get(
"/api/category/:name",
async(req,res)=>{

try{

const products=
await productDB.getCategory(
req.params.name
);

res.json({

success:true,

products

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   RELATED PRODUCTS
========================= */

app.get(
"/api/products/:id/related",
async(req,res)=>{

try{

const products=
await productDB.getRelatedProducts(
req.params.id
);

res.json({

success:true,

products

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   RECOMMEND PRODUCTS
========================= */

app.get(
"/api/recommend",
async(req,res)=>{

try{

const products=
await productDB.getRecommendProducts();

res.json({

success:true,

products

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   ADD FAVORITE
========================= */

app.post(
"/api/favorites/:productId",

requireLogin,

async(req,res)=>{

try{

const favorite=
await favoriteDB.addFavorite(

req.session.userId,

req.params.productId

);

res.json({

success:true,

favorite

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   REMOVE FAVORITE
========================= */

app.delete(
"/api/favorites/:productId",

requireLogin,

async(req,res)=>{

try{

await favoriteDB.removeFavorite(

req.session.userId,

req.params.productId

);

res.json({

success:true

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   MY FAVORITES
========================= */

app.get(
"/api/favorites",

requireLogin,

async(req,res)=>{

try{

const products=
await favoriteDB.getUserFavorites(

req.session.userId

);

res.json({

success:true,

products

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   IS FAVORITE
========================= */

app.get(
"/api/favorites/:productId/check",

requireLogin,

async(req,res)=>{

try{

const favorite=
await favoriteDB.isFavorite(

req.session.userId,

req.params.productId

);

res.json({

success:true,

favorite

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   FOLLOW USER
========================= */

app.post(
"/api/follow/:sellerId",

requireLogin,

async(req,res)=>{

try{

const follow=
await followDB.followUser(

req.session.userId,

req.params.sellerId

);

res.json({

success:true,

follow

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   UNFOLLOW USER
========================= */

app.delete(
"/api/follow/:sellerId",

requireLogin,

async(req,res)=>{

try{

await followDB.unfollowUser(

req.session.userId,

req.params.sellerId

);

res.json({

success:true

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   CHECK FOLLOW
========================= */

app.get(
"/api/follow/:sellerId/check",

requireLogin,

async(req,res)=>{

try{

const following=
await followDB.isFollowing(

req.session.userId,

req.params.sellerId

);

res.json({

success:true,

following

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   MY FOLLOWING
========================= */

app.get(
"/api/following",

requireLogin,

async(req,res)=>{

try{

const users=
await followDB.getFollowing(

req.session.userId

);

res.json({

success:true,

users

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   MY FOLLOWERS
========================= */

app.get(
"/api/followers",

requireLogin,

async(req,res)=>{

try{

const users=
await followDB.getFollowers(

req.session.userId

);

res.json({

success:true,

users

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   FOLLOW STATS
========================= */

app.get(
"/api/follow/stats",

requireLogin,

async(req,res)=>{

try{

const followers=
await followDB.getFollowerCount(
req.session.userId
);

const following=
await followDB.getFollowingCount(
req.session.userId
);

res.json({

success:true,

followers,

following

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   SEND CHAT
========================= */

app.post(
"/api/chat/send",

requireLogin,

uploadChat.single("image"),

async(req,res)=>{

try{

const image=req.file
?"/uploads/chat/"+req.file.filename
:"";

const chat=
await chatDB.sendMessage({

productId:req.body.productId||null,

fromUserId:req.session.userId,

toUserId:req.body.toUserId,

message:req.body.message||"",

image

});

if(req.body.toUserId){

await notificationDB.createNotification({

userId:req.body.toUserId,

fromUserId:req.session.userId,

productId:req.body.productId||null,

type:"chat",

title:"Pesan Baru",

message:req.body.message||"Mengirim gambar"

});

}

res.json({

success:true,

chat

});

}catch(err){

console.log(err);

res.status(500).json({

success:false,

message:err.message

});

}

}
);

/* =========================
   CHAT ROOM
========================= */

app.get(
"/api/chat/:userId",

requireLogin,

async(req,res)=>{

try{

await chatDB.markAsRead(

req.params.userId,

req.session.userId

);

const messages=
await chatDB.getMessages(

req.session.userId,

req.params.userId

);

res.json({

success:true,

messages

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   INBOX
========================= */

app.get(
"/api/inbox",

requireLogin,

async(req,res)=>{

try{

const inbox=
await chatDB.getInbox(

req.session.userId

);

res.json({

success:true,

inbox

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   DELETE CHAT
========================= */

app.delete(
"/api/chat/:id",

requireLogin,

async(req,res)=>{

try{

const chat=
await chatDB.deleteMessage(

req.params.id,

req.session.userId

);

res.json({

success:true,

chat

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   CHAT UNREAD
========================= */

app.get(
"/api/chat/unread",

requireLogin,

async(req,res)=>{

try{

const total=
await chatDB.getUnreadCount(

req.session.userId

);

res.json({

success:true,

total

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   PRODUCT CHAT
========================= */

app.get(
"/api/products/:id/chat",

requireLogin,

async(req,res)=>{

try{

const chats=
await chatDB.getProductChat(

req.params.id

);

res.json({

success:true,

chats

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   TYPING START
========================= */

app.post(
"/api/chat/typing",

requireLogin,

(req,res)=>{

typingUsers[

req.session.userId

]={

to:req.body.toUserId,

typing:true,

time:Date.now()

};

res.json({

success:true

});

}
);

/* =========================
   TYPING STOP
========================= */

app.delete(
"/api/chat/typing",

requireLogin,

(req,res)=>{

delete typingUsers[

req.session.userId

];

res.json({

success:true

});

}
);

/* =========================
   GET TYPING
========================= */

app.get(
"/api/chat/typing/:userId",

requireLogin,

(req,res)=>{

const user=

typingUsers[

req.params.userId

];

const typing=

!!(

user&&

user.to==req.session.userId

);

res.json({

success:true,

typing

});

}
);

/* =========================
   CREATE ORDER
========================= */

app.post(
"/api/orders",

requireLogin,

async(req,res)=>{

try{

const order=
await orderDB.createOrder({

productId:req.body.productId,

buyerId:req.session.userId,

sellerId:req.body.sellerId,

meetingPoint:req.body.meetingPoint,

meetingDate:req.body.meetingDate,

meetingTime:req.body.meetingTime

});

await notificationDB.createNotification({

userId:req.body.sellerId,

fromUserId:req.session.userId,

productId:req.body.productId,

type:"order",

title:"Pesanan Baru",

message:"Ada permintaan transaksi COD"

});

res.json({

success:true,

order

});

}catch(err){

console.log(err);

res.status(500).json({

success:false,

message:err.message

});

}

}
);

/* =========================
   ORDER DETAIL
========================= */

app.get(
"/api/orders/:id",

requireLogin,

async(req,res)=>{

try{

const order=
await orderDB.getOrder(
req.params.id
);

res.json({

success:true,

order

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   BUYER ORDERS
========================= */

app.get(
"/api/my-orders",

requireLogin,

async(req,res)=>{

try{

const orders=
await orderDB.getBuyerOrders(
req.session.userId
);

res.json({

success:true,

orders

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   SELLER ORDERS
========================= */

app.get(
"/api/seller-orders",

requireLogin,

async(req,res)=>{

try{

const orders=
await orderDB.getSellerOrders(
req.session.userId
);

res.json({

success:true,

orders

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   UPDATE ORDER STATUS
========================= */

app.put(
"/api/orders/:id/status",

requireLogin,

async(req,res)=>{

try{

const order=
await orderDB.updateStatus(

req.params.id,

req.body.status

);

res.json({

success:true,

order

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   CREATE OFFER
========================= */

app.post(
"/api/offers",

requireLogin,

async(req,res)=>{

try{

const offer=
await offerDB.createOffer({

productId:req.body.productId,

buyerId:req.session.userId,

sellerId:req.body.sellerId,

price:req.body.price

});

await notificationDB.createNotification({

userId:req.body.sellerId,

fromUserId:req.session.userId,

productId:req.body.productId,

type:"offer",

title:"Penawaran Baru",

message:"Seseorang menawar produk Anda"

});

res.json({

success:true,

offer

});

}catch(err){

console.log(err);

res.status(500).json({

success:false,

message:err.message

});

}

}
);

/* =========================
   BUYER OFFERS
========================= */

app.get(
"/api/my-offers",

requireLogin,

async(req,res)=>{

try{

const offers=
await offerDB.getBuyerOffers(
req.session.userId
);

res.json({

success:true,

offers

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   SELLER OFFERS
========================= */

app.get(
"/api/seller-offers",

requireLogin,

async(req,res)=>{

try{

const offers=
await offerDB.getSellerOffers(
req.session.userId
);

res.json({

success:true,

offers

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   UPDATE OFFER STATUS
========================= */

app.put(
"/api/offers/:id/status",

requireLogin,

async(req,res)=>{

try{

const offer=
await offerDB.updateOfferStatus(

req.params.id,

req.body.status

);

res.json({

success:true,

offer

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   DELETE OFFER
========================= */

app.delete(
"/api/offers/:id",

requireLogin,

async(req,res)=>{

try{

await offerDB.deleteOffer(

req.params.id,

req.session.userId

);

res.json({

success:true

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   CREATE REVIEW
========================= */

app.post(
"/api/reviews",

requireLogin,

async(req,res)=>{

try{

const review=
await reviewDB.createReview({

sellerId:req.body.sellerId,

buyerId:req.session.userId,

rating:req.body.rating,

comment:req.body.comment

});

if(!review){

return res.json({

success:false,

message:"Anda sudah memberi ulasan"

});

}

await notificationDB.createNotification({

userId:req.body.sellerId,

fromUserId:req.session.userId,

type:"review",

title:"Ulasan Baru",

message:"Seseorang memberikan ulasan"

});

res.json({

success:true,

review

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   SELLER REVIEWS
========================= */

app.get(
"/api/reviews/:sellerId",
async(req,res)=>{

try{

const reviews=
await reviewDB.getSellerReviews(
req.params.sellerId
);

const rating=
await reviewDB.getAverageRating(
req.params.sellerId
);

res.json({

success:true,

rating,

reviews

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   UPDATE REVIEW
========================= */

app.put(
"/api/reviews/:id",

requireLogin,

async(req,res)=>{

try{

const review=
await reviewDB.updateReview(

req.params.id,

req.session.userId,

req.body

);

res.json({

success:true,

review

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   DELETE REVIEW
========================= */

app.delete(
"/api/reviews/:id",

requireLogin,

async(req,res)=>{

try{

await reviewDB.deleteReview(

req.params.id,

req.session.userId

);

res.json({

success:true

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   GET NOTIFICATIONS
========================= */

app.get(
"/api/notifications",

requireLogin,

async(req,res)=>{

try{

const notifications=
await notificationDB.getNotifications(

req.session.userId

);

res.json({

success:true,

notifications

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   UNREAD NOTIFICATIONS
========================= */

app.get(
"/api/notifications/unread",

requireLogin,

async(req,res)=>{

try{

const total=
await notificationDB.getUnreadCount(

req.session.userId

);

res.json({

success:true,

total

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   READ NOTIFICATION
========================= */

app.put(
"/api/notifications/:id/read",

requireLogin,

async(req,res)=>{

try{

await notificationDB.readNotification(

req.params.id,

req.session.userId

);

res.json({

success:true

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   READ ALL NOTIFICATIONS
========================= */

app.put(
"/api/notifications/read-all",

requireLogin,

async(req,res)=>{

try{

await notificationDB.readAll(

req.session.userId

);

res.json({

success:true

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   DELETE NOTIFICATION
========================= */

app.delete(
"/api/notifications/:id",

requireLogin,

async(req,res)=>{

try{

await notificationDB.deleteNotification(

req.params.id,

req.session.userId

);

res.json({

success:true

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   DELETE ALL NOTIFICATIONS
========================= */

app.delete(
"/api/notifications",

requireLogin,

async(req,res)=>{

try{

await notificationDB.deleteAll(

req.session.userId

);

res.json({

success:true

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   CREATE REPORT
========================= */

app.post(
"/api/reports",

requireLogin,

async(req,res)=>{

try{

const report=
await reportDB.createReport({

reporterId:req.session.userId,

productId:req.body.productId,

reason:req.body.reason

});

if(!report){

return res.json({

success:false,

message:"Produk sudah pernah dilaporkan"

});

}

res.json({

success:true,

report

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   SEND VERIFICATION
========================= */

app.post(
"/api/verifications",

requireLogin,

async(req,res)=>{

try{

const verification=
await verificationDB.createVerification({

userId:req.session.userId,

photo:req.body.photo,

ktp:req.body.ktp,

selfie:req.body.selfie

});

if(!verification){

return res.json({

success:false,

message:"Masih ada verifikasi yang diproses"

});

}

res.json({

success:true,

verification

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   MY VERIFICATION
========================= */

app.get(
"/api/verifications/me",

requireLogin,

async(req,res)=>{

try{

const verification=
await verificationDB.getUserVerification(

req.session.userId

);

res.json({

success:true,

verification

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   CREATE APPEAL
========================= */

app.post(
"/api/appeals",

requireLogin,

async(req,res)=>{

try{

const appeal=
await appealDB.createAppeal({

productId:req.body.productId,

sellerId:req.session.userId,

reason:req.body.reason

});

if(!appeal){

return res.json({

success:false,

message:"Banding sudah dikirim"

});

}

res.json({

success:true,

appeal

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   MY APPEALS
========================= */

app.get(
"/api/appeals",

requireLogin,

async(req,res)=>{

try{

const appeals=
await appealDB.getUserAppeals(

req.session.userId

);

res.json({

success:true,

appeals

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   ADMIN DASHBOARD
========================= */

app.get(
"/api/admin/dashboard",

requireLogin,
requireAdmin,

async(req,res)=>{

try{

const dashboard=
await adminDB.getDashboard();

res.json({

success:true,

dashboard

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   ADMIN USERS
========================= */

app.get(
"/api/admin/users",

requireLogin,
requireAdmin,

async(req,res)=>{

try{

const users=
await adminDB.getUsers();

res.json({

success:true,

users

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   ADMIN PRODUCTS
========================= */

app.get(
"/api/admin/products",

requireLogin,
requireAdmin,

async(req,res)=>{

try{

const products=
await adminDB.getProducts();

res.json({

success:true,

products

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   CHANGE USER ROLE
========================= */

app.put(
"/api/admin/users/:id/role",

requireLogin,
requireAdmin,

async(req,res)=>{

try{

const user=
await adminDB.changeRole(

req.params.id,

req.body.role

);

res.json({

success:true,

user

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   BLOCK / UNBLOCK USER
========================= */

app.put(
"/api/admin/users/:id/block",

requireLogin,
requireAdmin,

async(req,res)=>{

try{

const user=
await adminDB.blockUser(
req.params.id
);

res.json({

success:true,

user

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   DISABLE PRODUCT
========================= */

app.put(
"/api/admin/products/:id/disable",

requireLogin,
requireAdmin,

async(req,res)=>{

try{

const product=
await adminDB.disableProduct(

req.params.id,

req.body.reason,

req.session.userId

);

res.json({

success:true,

product

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   ENABLE PRODUCT
========================= */

app.put(
"/api/admin/products/:id/enable",

requireLogin,
requireAdmin,

async(req,res)=>{

try{

const product=
await adminDB.enableProduct(
req.params.id
);

res.json({

success:true,

product

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   REPORTS
========================= */

app.get(
"/api/admin/reports",

requireLogin,
requireAdmin,

async(req,res)=>{

try{

const reports=
await reportDB.getReports();

res.json({

success:true,

reports

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   VERIFICATIONS
========================= */

app.get(
"/api/admin/verifications",

requireLogin,
requireAdmin,

async(req,res)=>{

try{

const verifications=
await verificationDB.getPendingVerifications();

res.json({

success:true,

verifications

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   APPROVE VERIFICATION
========================= */

app.put(
"/api/admin/verifications/:id/approve",

requireLogin,
requireAdmin,

async(req,res)=>{

try{

const verification=
await verificationDB.approveVerification(
req.params.id
);

res.json({

success:true,

verification

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   REJECT VERIFICATION
========================= */

app.put(
"/api/admin/verifications/:id/reject",

requireLogin,
requireAdmin,

async(req,res)=>{

try{

const verification=
await verificationDB.rejectVerification(
req.params.id
);

res.json({

success:true,

verification

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   APPEALS
========================= */

app.get(
"/api/admin/appeals",

requireLogin,
requireAdmin,

async(req,res)=>{

try{

const appeals=
await appealDB.getAppeals();

res.json({

success:true,

appeals

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   APPROVE APPEAL
========================= */

app.put(
"/api/admin/appeals/:id/approve",

requireLogin,
requireAdmin,

async(req,res)=>{

try{

const appeal=
await appealDB.approveAppeal(
req.params.id
);

res.json({

success:true,

appeal

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   REJECT APPEAL
========================= */

app.put(
"/api/admin/appeals/:id/reject",

requireLogin,
requireAdmin,

async(req,res)=>{

try{

const appeal=
await appealDB.rejectAppeal(
req.params.id
);

res.json({

success:true,

appeal

});

}catch(err){

console.log(err);

res.status(500).json({

success:false

});

}

}
);

/* =========================
   ROOT
========================= */

app.get("/",(req,res)=>{

res.sendFile(

path.join(

__dirname,

"public",

"index.html"

)

);

});

app.get("/api",(req,res)=>{

res.json({

success:true,

app:"MarketplaceID",

version:"4.0.0",

database:"PostgreSQL",

status:"Running"

});

});

/* =========================
   START SERVER
========================= */

async function startServer(){

try{

await db.testConnection();

app.listen(PORT,()=>{

console.log("");

console.log("==============================");

console.log("🚀 MarketplaceID Running");

console.log("🌐 Port :",PORT);

console.log("🗄 Database : PostgreSQL");

console.log("==============================");

console.log("");

});

}catch(err){

console.log(err);

process.exit(1);

}

}

startServer();
