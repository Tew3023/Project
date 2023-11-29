const multer = require("multer");


//set upload directory and rename upload file with timestamp
const storageOption = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'public/upload/')
    },
    filename: function (req, file, cb) {
        //rename file with timestamp as prefix
        cb(null, Date.now() + "_" + file.originalname);
        // to get only file extension -> path.extname(file.originalname)
        // to get only filename -> path.basename(fileName, path.extname(file.originalname))
    }
});


// set upload option and input fieldname
// also limit file size to 100 KB
const upload = multer({ storage: storageOption, limits: {fileSize: 100*1000} }).single("filetoupload");


module.exports = upload;

